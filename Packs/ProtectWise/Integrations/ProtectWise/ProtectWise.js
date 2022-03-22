var DEFAULT_EVENT_HEADERS = ['message','id','type','sensorId','threatScore','killChainStage','confidence','startedAt','observedAt','endedAt','observationCount','netflowCount','observedStage'];
var DEFAULT_NETFLOW_HEADERS = ['key', 'id.srcIp', 'id.dstIp', 'id.srcPort', 'id.dstPort', 'id.layer4Proto'];
var DEFAULT_OBSERVATION_HEADERS = ['id','killChainStage','source','sensorId','threatScore','severity','confidence','occurredAt','observedAt','endedAt','netflowId','observedStage'];
var DEFAULT_SENSOR_HEADERS = ['id', 'friendly_name', 'ip_address', 'last_seen', 'customer_id', 'enabled'];
var TIME_FIELDS = ['startedAt', 'occurredAt', 'endedAt', 'observedAt'];

var serverUrl = params.url.replace(/[\/]+$/, '') + '/';

var getToken = function() {
    var token = '';
    if ((params.token) && (params.token.length > 0)) {
        token = params.token;
    }
    if (token.length === 0) {
        if (params.email.length === 0 || params.password.length === 0){
            throw 'If token configuration is empty , you must provide email+password configuration params for auth';
        }
        var tokResult = http(
            serverUrl + 'token',
            {
                Headers: {'Content-Type': ['application/json']},
                Method: 'POST',
                Body: JSON.stringify({'email': params.email, 'password': params.password}),
            },
            params.insecure,
            params.proxy
        );
        var body;
        if (tokResult.StatusCode !== 200 && tokResult.StatusCode !== 201) {
            throw 'Failed to create token, request status code: ' + tokResult.StatusCode + ', body: ' + tokResult.Body;
        }
        try {
            body = JSON.parse(tokResult.Body);
        } catch (ex) {
            throw 'Error parsing token - ' + tokResult.Body + ' - ' + ex;
        }

        return body.token;
    }
    return token;
};

// If value for any argument is empty remove it
var cleanArgs = function(args) {
    return Object.keys(args).filter(function(k) {return args[k];}).reduce(function(clean, k) {clean[k] = args[k]; return clean;}, {});
};

var doReq = function(url, token, raw, args, saveToFile) {
    if (args) {
        url += encodeToURLQuery(cleanArgs(args));
    }
    var res = http(
        url,
        {
            Headers: {'X-Access-Token': [ token ]},
            Method: 'GET',
            SaveToFile: saveToFile ? true : false
        },
        params.insecure,
        params.proxy
        );
    if (res.StatusCode !== 200) {
        throw 'Failed to execute ' + url + ' : ' + res.StatusCode + ', body: ' + res.Body;
    }
    try {
        return (raw ? (saveToFile ? res.Path : res.Body) : JSON.parse(res.Body));
    } catch (ex) {
        throw 'Error parsing response - ' + res.Body + ' - ' + ex;
    }
};

var filterClone = function(src, filter) {
    if (src && Array.isArray(src) && filter && Array.isArray(filter)) {
        var items = [];
        src.forEach(function(s) {
            var item = {};
            filter.forEach(function( col ) {
               item[col] =  dq(s, col);
            });
            items.push(item);
        });
        return items;
    } else return undefined;
};

var parseTime = function(time) {
    if ((typeof time === 'string' || time instanceof String) && (time.indexOf("-") >= 0 || time.indexOf("/") >= 0 )){
        var d = new Date(time);
        return d.getTime();
    }
    return time;
};

var eventsSearch = function(start, end, eventType, killChainStage, threatLevel, threatCategory, observationStage, ip, expandDetails, minLimit, maxLimit, reverseOrder, nextPage, token) {
    return doReq(serverUrl + 'events', token, true, {start: parseTime(start), end: parseTime(end),
        eventType: eventType, killChainStage: killChainStage, threatLevel: threatLevel, threatCategory: threatCategory, observationStage: observationStage,
        ip: ip, expandDetails: expandDetails, minLimit: minLimit, maxLimit: maxLimit, reverseOrder: reverseOrder, nextPage: nextPage});
};

var observationSearch = function(sensorId,start,end,type,killChainStage,threatLevel,threatCategory,hasKillChain,ip,expandDetails,minLimit,maxLimit,reverseOrder,nextPage,signatureId,token) {
    return doReq(serverUrl + 'observations', token, true, {sensorId: sensorId, start: parseTime(start), end: parseTime(end), type: type, killChainStage: killChainStage,
        threatLevel: threatLevel, threatCategory: threatCategory, hasKillChain: hasKillChain, ip: ip, expandDetails: expandDetails, minLimit: minLimit, maxLimit: maxLimit,
        reverseOrder: reverseOrder, nextPage: nextPage, signatureId: signatureId});
};

var createIncidentFromEvent = function(event) {
    var keys = Object.keys(event);
    var labels = [];
    for (var i = 0; i<keys.length; i++) {
        val = event[keys[i]];
        if (TIME_FIELDS.indexOf(keys[i]) > -1) {
            val = convertTimestampToString(val);
        }
        labels.push({'type': keys[i], 'value': String(val)});
    }
    return {
        "name": event.message,
        "labels": labels,
        "rawJSON": JSON.stringify(event),
        "occurred": convertTimestampToString(event.observedAt)
    };
};

var token = getToken();
switch (command) {
    case 'test-module':
        if (token && token.length > 0) {
            return true;
        }
        return false;
    case 'fetch-incidents':
        var lastRun = getLastRun();
        var now = (new Date()).getTime();
        if (!lastRun || !lastRun.time) {
            // First time, retrieve events from the last 10 min
            lastRun = {time: now - 10 * 60 * 1000};
        }
        var data = eventsSearch(lastRun.time , now , params.eventType, params.killChainStage, params.threatLevel,
            params.threatCategory, null, null, null, null, null, null, null, token);
        try {
            var res = JSON.parse(data).events;
            res.reverse();  // events are fetched in descending order so reversing to process older first
        } catch (ex) {
            throw 'Error parsing event fetch - ' + data + ' - ' + ex;
        }
        var incidents = [];
        for (var i = 0; i < res.length; i++) {
            if (incidents.length >= Math.min(parseInt(params.maxFetch), 50)) {
                break;
            }
            var skip = true;
            if (params.messageFilter && res[i].message) {
                filters = params.messageFilter.split(',');
                for (var j = 0; j < filters.length; j++) {
                    if (filters[j] && filters[j].length > 0 && res[i].message.toLowerCase().indexOf(filters[j].toLowerCase()) > -1) {
                        skip = false;
                        break;
                    }
                }
            } else {
                skip = false;
            }
            if(!skip) {
                incidents.push(createIncidentFromEvent(res[i]));
                lastRun.time = Math.max(lastRun.time, res[i].startedAt)+1;
            }
        }
        setLastRun(lastRun);
        return JSON.stringify(incidents);
    case 'sensors':
    case 'protectwise-show-sensors':
        var url = serverUrl + 'sensors';
        if (args.sensorId && args.sensorId.length > 0 ) {
            url = url + '/' + args.sensorId;
        }
        var headers = args.headers ? args.headers : DEFAULT_SENSOR_HEADERS;

        var res = doReq(url, token);
        var items = [];

        if (!Array.isArray(res)) {
            res = [res];
        }
        items = filterClone(res, headers);

        return {
            Type: entryTypes.note,
            Contents: res,
            ContentsFormat: formats.json,
            HumanReadable: tableToMarkdown('Protectwise sensors', items, headers),
            EntryContext: {'Protectwise.Sensor(val.id == obj.id)': items}
        };
    case 'search':
    case 'protectwise-search-events':
        var res;
        var raw = eventsSearch(args.start, args.end, args.eventType, args.killChainStage, args.threatLevel,
            args.threatCategory, args.observationStage, args.ip, args.expandDetails, args.minLimit, args.maxLimit, args.reverseOrder, args.nextPage, token);
        try {
            res = JSON.parse(raw).events;
        } catch (ex) {
            throw 'Error parsing event search - ' + raw + ' - ' + ex;
        }
        var eventHeaders = args.headers ? args.headers : DEFAULT_EVENT_HEADERS;
        var items = [];
        if (!Array.isArray(res)) {
            res = [res];
        }
        items = filterClone(res, eventHeaders);
        items.forEach(function(item) {
           TIME_FIELDS.forEach(function (timeKey) {
               if (item[timeKey]) {
                   item[timeKey] = convertTimestampToString(item[timeKey]);
               }
           });
        });

        return {
            Type: entryTypes.note,
            Contents: raw,
            ContentsFormat: formats.json,
            HumanReadable: tableToMarkdown('Protectwise Event Search', items, eventHeaders),
            EntryContext: {'Protectwise.Event(val.id == obj.id)': items}
        };
    case 'pw-event-get':
    case 'protectwise-event-info':
        var url = serverUrl + 'events/' + args.id;
        var eventHeaders = args.headers ? args.headers : DEFAULT_EVENT_HEADERS;
        var res = doReq(url, token);
        var event = {};
        eventHeaders.forEach(function( col ) {
           event[col] = res[col];
        });

        TIME_FIELDS.forEach(function (timeKey) {
           if (event[timeKey]) {
               event[timeKey] = convertTimestampToString(event[timeKey]);
           }
        });

        var md = tableToMarkdown('Protectwise Event ' + res.id, [event], eventHeaders);

        if (res.netflows && res.netflows.length > 0) {
            var nf = filterClone(res.netflows, DEFAULT_NETFLOW_HEADERS);
            for(var i = 0; i < nf.length; i++) {
                nf[i].srcIp = nf[i]['id.srcIp'];
                nf[i].dstIp = nf[i]['id.dstIp'];
                nf[i].srcPort  = nf[i]['id.srcPort'];
                nf[i].dstPort = nf[i]['id.dstPort'];
                nf[i].layer4Proto = nf[i]['id.layer4Proto'];
                }
            event.Netflows = nf;
            md += '\n' + tableToMarkdown('Related Netflows', nf, DEFAULT_NETFLOW_HEADERS);
        }

        if (res.observations && res.observations.length > 0) {
            var obs = filterClone(res.observations, DEFAULT_OBSERVATION_HEADERS);
            obs.forEach(function(item) {
                TIME_FIELDS.forEach(function (timeKey) {
                   if (item[timeKey]) {
                       item[timeKey] = convertTimestampToString(item[timeKey]);
                   }
               });
            });
            event.Observations = obs;
            md += '\n' + tableToMarkdown('Related Observations', obs, DEFAULT_OBSERVATION_HEADERS);
        }

        return {
            Type: entryTypes.note,
            Contents: res,
            ContentsFormat: formats.json,
            HumanReadable: md,
            EntryContext: {'Protectwise.Event(val.id == obj.id)': event}
        };
    case 'observation-search':
    case 'protectwise-search-observations':
        var res;
        var raw = observationSearch(args.sensorId, args.start, args.end, args.type, args.killChainStage, args.threatLevel,
            args.threatCategory, args.hasKillChain, args.ip, args.expandDetails, args.minLimit, args.maxLimit, args.reverseOrder, args.nextPage, args.signatureId, token);
        try {
            res = JSON.parse(raw).observations;
        } catch (ex) {
            throw 'Error parsing observation search - ' + raw + ' - ' + ex;
        }
        var headers = args.headers ? args.headers : DEFAULT_OBSERVATION_HEADERS;
        var items = [];
        if (!Array.isArray(res)) {
            res = [res];
        }
        items = filterClone(res, headers);
        items.forEach(function(item) {
            TIME_FIELDS.forEach(function (timeKey) {
               if (item[timeKey]) {
                   item[timeKey] = convertTimestampToString(item[timeKey]);
               }
           });
        });

        return {
            Type: entryTypes.note,
            Contents: raw,
            ContentsFormat: formats.json,
            HumanReadable: tableToMarkdown('Protectwise Observation Search', items, headers),
            EntryContext: {'Protectwise.Observation(val.id == obj.id)': items}
        };
    case 'pw-observation-get':
    case 'protectwise-observation-info':
        var url = serverUrl + 'observations/' + args.id;
        var headers = args.headers ? args.headers : DEFAULT_OBSERVATION_HEADERS;
        var res = doReq(url, token, false, {'sensorId': args.sensorId});
        var obj = {};
        headers.forEach(function( col ) {
           obj[col] = res[col];
        });
        TIME_FIELDS.forEach(function (timeKey) {
           if (obj[timeKey]) {
               obj[timeKey] = convertTimestampToString(obj[timeKey]);
           }
        });

        var md = tableToMarkdown('Protectwise Observation ' + res.id, [obj], headers);
        return {
            Type: entryTypes.note,
            Contents: res,
            ContentsFormat: formats.json,
            HumanReadable: md,
            EntryContext: {'Protectwise.Observation(val.id == obj.id)': obj}
        };
    case 'event-pcap-download':
    case 'protectwise-event-pcap-download':
        var filename = (args.filename && args.filename.length > 0) ? args.filename : (args.eventId + '.pcap');

        var url = serverUrl + 'pcaps/events/' + args.eventId;
        res = doReq(url, token, true, {filename: filename}, true);
        return {Type: 3, FileID: res, File: filename, Contents: 'we must have contents for an entry'};
    case 'event-pcap-info':
    case 'protectwise-event-pcap-info':
        var url = serverUrl + 'pcaps/events/'+ args.eventId + '/info';
        var res = doReq(url, token);
        var md = '### Protectwise PCAP for Event ' + res.id + '\n - Estimated size: ' + res.estimatedSize + ' bytes';
        if (res.netflows && res.netflows.length > 0) {
            var nf = filterClone(res.netflows, DEFAULT_NETFLOW_HEADERS);
                for(var i = 0; i < nf.length; i++) {
                    nf[i].srcIp = nf[i]['id.srcIp'];
                    nf[i].dstIp = nf[i]['id.dstIp'];
                    nf[i].srcPort  = nf[i]['id.srcPort'];
                    nf[i].dstPort = nf[i]['id.dstPort'];
                    nf[i].layer4Proto = nf[i]['id.layer4Proto'];
                }
            event.Netflows = nf;
            md += '\n' + tableToMarkdown('Included Netflows', res.netflows);
        }

        return {
            Type: entryTypes.note,
            Contents: res,
            ContentsFormat: formats.json,
            HumanReadable: md,
            EntryContext: {'Protectwise.Event(val.id == obj.id)': {'id': res.id, 'PCAPSize': res.estimatedSize}}
        };
    case 'observation-pcap-download':
    case 'protectwise-observation-pcap-download':
        var filename = (args.filename && args.filename.length > 0) ? args.filename : ( args.sensorId+'-'+args.id + '.pcap');
        var url = serverUrl + 'pcaps/observations/' + args.sensorId + '/' + args.id;
        res = doReq(url, token, true, {filename: filename}, true);
        return {Type: 3, FileID: res, File: filename, Contents: 'we must have contents for an entry'};
    case 'observation-pcap-info':
    case 'protectwise-observation-pcap-info':
        var url = serverUrl + 'pcaps/observations/' + args.sensorId + '/' + args.id + '/info';
        var res = doReq(url, token);
        var md = '### Protectwise PCAP for Observation ' + res.id + '\n - Estimated size: ' + res.estimatedSize + ' bytes';
        if (res.netflows && res.netflows.length > 0) {
            var nf = filterClone(res.netflows, DEFAULT_NETFLOW_HEADERS);
                for(var i = 0; i < nf.length; i++) {
                    nf[i].srcIp = nf[i]['id.srcIp'];
                    nf[i].dstIp = nf[i]['id.dstIp'];
                    nf[i].srcPort  = nf[i]['id.srcPort'];
                    nf[i].dstPort = nf[i]['id.dstPort'];
                    nf[i].layer4Proto = nf[i]['id.layer4Proto'];
                }
            event.Netflows = nf;
            md += '\n' + tableToMarkdown('Included Netflows', res.netflows);
        }

        return {
            Type: entryTypes.note,
            Contents: res,
            ContentsFormat: formats.json,
            HumanReadable: md,
            EntryContext: {'Protectwise.Observation(val.id == obj.id && val.sensorId == obj.sensorId)': {'id': args.id, 'sensorId': args.sensorId, 'PCAPSize': res.estimatedSize}}
        };
    case 'get-token':
        return token;
    default:
        return 'The Protectwise integration has no command "' + command + '"';
}
