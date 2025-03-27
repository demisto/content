var server = params.url.replace(/[\/]+$/, '') + '/' + params.apiVersion + '/';

var doReq = function(method, path, parameters, cookies) {
    var username = params.credentialsAccess.identifier || params.accessID;
    var password = params.credentialsAccess.password || params.accessKey;
    if ((!username)||(!password)){
        return 'Access key and Access ID must be provided.';
    }
    var result = http(
        server + path + (method === 'GET' && parameters ? encodeToURLQuery(parameters) : ''),
        {
            Headers: {'Content-Type': ['application/json'], 'Accept': ['application/json']},
            Method: method,
            Body: method == 'POST' && parameters ? JSON.stringify(parameters) : '',
            Username: username,
            Password: password,
            Cookies: cookies
        },
        params.insecure,
        params.useproxy
    );
    if (result.StatusCode < 200 || result.StatusCode > 299) {
        var errObj;
        try {
            errObj = JSON.parse(result.Body);
        } catch (ex) {
            // Ignore this - we will just throw the status code back
        }
        if (errObj) {
            throw 'Status: ' + result.StatusCode + '\nID: ' + errObj.id + '\nCode: ' + errObj.code + '\nMessage: ' + errObj.message;
        }
        throw 'Failed to perform request ' + path + ', request status code: ' + result.StatusCode;
    }
    if (result.Body === '') {
        throw 'No content received.';
    }
    var obj;
    try {
        obj = JSON.parse(result.Body);
    } catch (ex) {
        throw 'Error parsing reply - ' + result.Body + ' - ' + ex;
    }
    return {body: result.Body, obj: obj, statusCode: result.StatusCode, cookies: result.Cookies};
};

var search = function(query, from, to, limit, offset, timezone, maxTimeToWaitForResults, byReceiptTime, sleep, waitForSearchComplete) {
    var p = {query: query};
    if (from) {
        p.from = from;
    }
    if (to) {
        p.to = to;
    }
    if (timezone) {
        p.timeZone = timezone;
    }
    if (byReceiptTime) {
        p.byReceiptTime = byReceiptTime;
    }
    // Create the job
    var res = doReq('POST', 'search/jobs', p, null);
    try {
        var done = false;
        var stat;
        // Wait for results based on parameters
        for (var i=0; i<maxTimeToWaitForResults / sleep; i++) {
            wait(sleep);
            stat = doReq('GET', 'search/jobs/' + res.obj.id, null, res.cookies);
            if (stat.obj.state === 'DONE GATHERING RESULTS' || (!waitForSearchComplete && stat.obj.messageCount > (offset + 1) * limit)) {
                done = true;
                break;
            }
            if (stat.obj.state === 'CANCELLED') {
                throw 'Job ' + res.obj.id + ' was cancelled';
            }
        }
        if (done) {
            var results = {};
            if (stat.obj.messageCount > 0) {
                var msg = doReq('GET', 'search/jobs/' + res.obj.id + '/messages', {offset: offset, limit: limit}, res.cookies);
                results.messages = msg.obj.messages.map(function(m) {return m.map;});
            }
            if (stat.obj.recordCount > 0) {
                var rec = doReq('GET', 'search/jobs/' + res.obj.id + '/records', {offset: offset, limit: limit}, res.cookies);
                results.records = rec.obj.records.map(function(m) {return m.map;});
            }
            return results;
        }
        throw 'Timeout while waiting for job ' + res.obj.id;
    } finally {
        try {
            doReq('DELETE', 'search/jobs/' + res.obj.id, null, res.cookies);
        } catch (ex) {
            logInfo('SumoLogic error deleting job - ' + ex);
        }
    }
};

var a2i = function(v, d) {
    return v ? parseInt(v) : d;
};

var defaultLimit = 100, defaultSleep = 3, defaultTimeout = 180, defaultSearchTimeout = 10;
var limit = a2i(params.limit, defaultLimit)

switch (command) {
    // This is the call made when pressing the integration test button.
    case 'test-module':
        doReq('GET', 'collectors', {limit: '3'}, null);
        return 'ok';
    case 'fetch-incidents':
        if (!params.fetchQuery) {
            throw 'No fetch query defined, not doing SumoLogic fetch';
        }
        var now = (new Date()).getTime();
        var lastRun = getLastRun();
        if (!lastRun || !lastRun.time) {
            lastRun = {time: now - parseInt(params.firstFetch) * 1000};
            setLastRun({time: now});
        }

        if (params.fetchDelay) {
            if (now < lastRun.time + parseInt(params.fetchDelay) * 1000) {
                return JSON.stringify([]);
            }
        }

        var s = search(params.fetchQuery, lastRun.time, now, limit, 0, params.timeZone, a2i(params.maxTimeout, 180), !params.fetchRecords,
            a2i(params.sleepBetweenChecks, defaultSleep), params.fetchRecords);
        var incidents = [];
        var currentFetch = lastRun.time;
        if (!params.fetchRecords && s.messages) {
            for (var i=0; i<s.messages.length; i++) {
                var incident = {name: 'Incident from SumoLogic' + s.messages[i]._messageid,
                    details: s.messages[i]._raw, labels: [], rawJSON: JSON.stringify(s.messages[i])};
                var props = Object.getOwnPropertyNames(s.messages[i]);
                for (var j=0; j<props.length; j++) {
                    if (props[j] !== '_raw') {
                        incident.labels.push({type: props[j], value: s.messages[i][props[j]]});
                    }
                }
                if (parseInt(s.messages[i]._receipttime) >= currentFetch){
                    currentFetch = parseInt(s.messages[i]._receipttime) + 1
                }
                incidents.push(incident);
            }
        }

        if (params.fetchRecords) {
            var updatedCurrentFetch = currentFetch;
            if (s.records) {
                for (var i=0; i<s.records.length; i++) {
                    var incident = {name: 'Incident from SumoLogic',
                        details: JSON.stringify(s.records[i]), labels: [], rawJSON: JSON.stringify(s.records[i])};
                    var props = Object.getOwnPropertyNames(s.records[i]);
                    for (var j=0; j<props.length; j++) {
                        if (props[j] !== '_raw') {
                            incident.labels.push({type: props[j], value: s.records[i][props[j]]});
                        }
                    }
                    var recordDate = new Date("{0}T{1}".format(s.records[i].date, s.records[i].time));
                    var recordDateEpoch = Math.ceil(recordDate);
                    if (recordDateEpoch >= updatedCurrentFetch){
                        updatedCurrentFetch = recordDateEpoch + 1
                    }
                    incidents.push(incident);
                }
            }

            // if no records were fetched, then we set the currentFetch to (now time - 1 minute) as in
            // later runs we could send a big query with old timestamp that could cause a timeout
            // we are setting to (now - 1 minute) to avoid missing events
            if (updatedCurrentFetch === currentFetch) {
                currentFetch = now - (60 * 1000);
            } else {
                currentFetch = updatedCurrentFetch;
            }
        }
        setLastRun({time: currentFetch});
        return JSON.stringify(incidents);
    case 'search':
        query = args.query
        if (params.escape_urls || typeof params.escape_urls === 'undefined' || params.escape_urls === null) {
            // fallback to ensure BC with instances set before v1.1.0
            var httpIndex = query.indexOf('http')
            if (httpIndex != -1) {
                var httpSubstring = query.substring(httpIndex)
                var whitespaceIndex = httpSubstring.indexOf(' ')
                var url = httpSubstring.substring(0, whitespaceIndex)
                url = url.replace(/=/g, '\\\\=')
                var beforeHttp = query.substring(0, httpIndex)
                var afterWhitespace = query.substring(httpIndex + whitespaceIndex)
                query = beforeHttp + url + afterWhitespace
            }
        }
        var headers = 'headers' in args ? argToList(args.headers) : undefined;
        var waitForSearchComplete = args.waitForSearchComplete == 'true';
        commandLimit = a2i(args.limit, limit)
        var s = search(query, args.from, args.to, commandLimit, a2i(args.offset, 0), args.timezone,
            a2i(args.maxTimeToWaitForResults, defaultSearchTimeout) * 60, args.byReceiptTime, a2i(params.sleepBetweenChecks, defaultSleep),
            waitForSearchComplete);
        var md = '';
        var ec = {};
        if (s.messages && s.messages.length > 0) {
            md = tableToMarkdown('SumoLogic Search Messages', s.messages, headers) + '\n';
            ec.Search = {Messages: s.messages.length > commandLimit ? s.messages.slice(0, commandLimit) : s.messages};
        }
        if (s.records && s.records.length > 0) {
            md += tableToMarkdown('SumoLogic Search Records', s.records, headers);
            ec.Search = {Records: s.records.length > commandLimit ? s.records.slice(0, commandLimit) : s.records};
        }
        if (!md) {
            md = 'No results found';
        }
        return {Type: entryTypes.note, Contents: s, ContentsFormat: formats.json, HumanReadable: md, EntryContext: ec};
    default:
        return {Type: entryTypes.error, Contents: 'Unknown command - ' + command, ContentsFormat: formats.text};
}
