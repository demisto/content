var serverURL = params.url;
if (serverURL.slice(-1) === '/') {
    serverURL = serverURL.slice(0,-1);
}
var SERVER_URL = serverURL + ':' + params.port + '/';
var DAY_IN_MILLIS = 24*60*60*1000;

function login(username, password) {
    var fullUrl = SERVER_URL + 'core-service/rest/LoginService/login';

    var bodyObj = {
        login: username,
        password: password
    };
    var bodyString = encodeToURLQuery(bodyObj).substring(1);

    var req = {
        Method: 'POST',
        Headers: {
            'Content-Type': ['application/x-www-form-urlencoded']
        },
        Body: bodyString
    };

    var res = http(fullUrl, req, params.insecure, params.proxy);
    if (res.StatusCode !== 200) {
        throw 'Login failed. StatusCode: ' + res.StatusCode + (res.Body !== '' ? '. Error: ' + res.Body : '');
    }

    var resBody = parseXML(res.Body);
    if (!resBody.loginResponse.return) {
        throw 'Login to ArcSight Logger has failed - Session id is missing from response';
    }

    var userSessionId = resBody.loginResponse.return;
    return userSessionId;
}

function logout(userSessionId) {
    if (!userSessionId) {
        throw 'Unable to preform logout from ArcSight Logger. Seesion id is missing';
    }
    var fullUrl = SERVER_URL + 'core-service/rest/LoginService/logout';

    var bodyObj = {
        authToken: userSessionId
    };
    var bodyString = encodeToURLQuery(bodyObj).substring(1);

    var req = {
        Method: 'POST',
        Headers: {
            'Content-Type': ['application/x-www-form-urlencoded']
        },
        Body: bodyString
    };

    var res = http(fullUrl, req, params.insecure, params.proxy);
    if (res.StatusCode !== 200 && res.StatusCode !== 204) {
        throw 'Logout failed. StatusCode: ' + res.StatusCode + (res.Body !== '' ? '. Error: ' + res.Body : '');
    }
}

function getSearchEvents(userSessionId) {
    var events = getSearchEventsRequest(
        userSessionId,
        args.query,
        args.timeout,
        args.startTime,
        args.endTime,
        args.discover_fields,
        args.summary_fields,
        args.field_summary,
        args.local_search,
        args.lastDays,
        args.offset,
        args.dir,
        args.length,
        args.fields);

    var entry = {
        Type: entryTypes.note,
        Contents: events,
        ContentsFormat: formats.json,
        ReadableContentsFormat: formats.markdown
    };
    var title = 'ArcSight Logger - Events';
    var context = events;
    entry.HumanReadable = tableToMarkdown(title, events);
    entry.EntryContext = {};
    entry.EntryContext['ArcSightLogger.Events(val.rowId === obj.rowId)'] = context;
    return entry;
}

function getSearchEventsRequest(userSessionId, query, timeout, startTime,
    endTime, discoverFields, summaryFields, fieldSummary, localSearch, lastDays,
    offset, dir, length, fields) {
    // start new search
    var searchSessionId = startSearchSessionRequest(
        userSessionId,
        query,
        timeout,
        startTime,
        endTime,
        discoverFields,
        summaryFields,
        fieldSummary,
        localSearch,
        lastDays);

    // wait until the search is complete so we could collect the events
    var statusResult;
    var requiredEvents = Infinity;
    if(length){
        requiredEvents = offset ? parseInt(length) + parseInt(offset) : parseInt (length);
    }
    do {
        wait(1);
        statusResult = getSearchStatusRequest(userSessionId, searchSessionId);
        if (statusResult.status === 'error') {
            throw 'Invalid query.\nSearch status: ' + JSON.stringify(statusResult, null ,2);
        }
    } while(statusResult.status !== 'complete' && requiredEvents > statusResult.hit);
    // get the results
    var events;
    if (statusResult.result_type === 'chart') {
        events = getChartRequest(userSessionId, searchSessionId);
    } else {
        events = getEventsRequest(userSessionId, searchSessionId, offset, dir, length, fields);
    }
    // close the session
    closeSessionRequest(userSessionId, searchSessionId);

    logout(userSessionId);
    return events;
}

function startSearchSession(userSessionId) {
    var searchSessionId = startSearchSessionRequest(
        userSessionId,
        args.query,
        args.timeout,
        args.startTime,
        args.endTime,
        args.discover_fields,
        args.summary_fields,
        args.field_summary,
        args.local_search,
        args.lastDays);

    var entry = {
        Type: entryTypes.note,
        Contents: {
            searchSessionId: searchSessionId,
            sessionId : userSessionId
        },
        ContentsFormat: formats.json,
        ReadableContentsFormat: formats.markdown
    };
    var title = "ArcSight Logger - Start Search Session";
    var context = {
        'SearchSessionId': searchSessionId,
        'SessionId' : userSessionId
    };
    entry.HumanReadable = tableToMarkdown(title, context);
    entry.EntryContext = {};
    entry.EntryContext['ArcSightLogger.Search'] = context;
    return entry;
}

function startSearchSessionRequest(userSessionId, query, timeout, startTime, endTime, discoverFields, summaryFields, fieldSummary, localSearch, lastDays) {
    var searchSessionId = generateSearchSessionId();
    var bodyArgs = {
        search_session_id: searchSessionId,
        user_session_id: userSessionId
    };
    if (query) {
        bodyArgs.query = query;
    }
    if (timeout) {
        bodyArgs.timeout = parseInt(timeout);
    }
    if (lastDays) {
        if (isNaN(lastDays)) {
            throw 'LastDays must be a number';
        }
        var ld = parseInt(lastDays);
        var now = new Date();
        bodyArgs.end_time = now.toISOString();
        now.setTime(now.getTime() - ld * DAY_IN_MILLIS)
        bodyArgs.start_time = now.toISOString();
    } else if (startTime && endTime) {
        bodyArgs.end_time = endTime;
        bodyArgs.start_time = startTime;
    }
    if (discoverFields) {
        bodyArgs.discover_fields = parseBool(discoverFields);
    }
    if (summaryFields) {
        bodyArgs.summary_fields = parseArray(summaryFields);
    }
    if (fieldSummary) {
        bodyArgs.field_summary = parseBool(fieldSummary);
    }
    if (localSearch) {
        bodyArgs.local_search = parseBool(localSearch);
    }

    var resBody = httpPost('server/search', null, bodyArgs);

    return searchSessionId;
}

function closeSession() {
    closeSessionRequest(args.sessionId, args.searchSessionId);
    return {
        Type: entryTypes.note,
        ContentsFormat: formats.text,
        Contents: 'Session closed successfully'
    };
}

function closeSessionRequest(userSessionId, searchSessionId) {
    var bodyArgs = {
        search_session_id: parseInt(searchSessionId),
        user_session_id: userSessionId
    };
    httpPost('server/search/close', null, bodyArgs);
}

function getSearchStatus() {
    var searchStatus = getSearchStatusRequest(args.sessionId, args.searchSessionId);
    var contextKey = 'ArcSightLogger.Status(val.SearchSessionId === obj.SearchSessionId)';
    var entry = createEntry(searchStatus, {
        data: [
            {to: 'Status', from: 'status'},
            {to: 'ResultType', from: 'result_type'},
            {to: 'Hit', from: 'hit'},
            {to: 'Scanned', from: 'scanned'},
            {to: 'Elapsed', from: 'elapsed'},
            {to: 'Message', from: 'message'}
        ],
        title: 'ArcSight Logger - Search Status',
        contextPath: contextKey
    });
    entry.EntryContext[contextKey]['SearchSessionId'] = args.searchSessionId;
    return entry;
}

function getSearchStatusRequest(userSessionId, searchSessionId) {
    var bodyArgs = {
        search_session_id: parseInt(searchSessionId),
        user_session_id: userSessionId
    };

    var resBody = httpPost('server/search/status', null, bodyArgs);
    return resBody;
}

function getEvents() {
    var statusResult = getSearchStatusRequest(
        args.sessionId,
        args.searchSessionId);
    var events;
    if (statusResult.result_type === 'chart'){
        events = getChartRequest(
            args.sessionId,
            args.searchSessionId);
    } else {
       events = getEventsRequest(
            args.sessionId,
            args.searchSessionId,
            args.offset,
            args.dir,
            args.length,
            args.fields);
    }
    var entry = {
        Type: entryTypes.note,
        Contents: events,
        ContentsFormat: formats.json,
        ReadableContentsFormat: formats.markdown
    };
    var title = 'ArcSight Logger - Events';
    var context = events;
    entry.HumanReadable = tableToMarkdown(title, events);
    entry.EntryContext = {};
    entry.EntryContext['ArcSightLogger.Events(val.rowId === obj.rowId)'] = context;
    return entry;
}

function getEventsRequest(userSessionId, searchSessionId, offset, dir, length, fields) {
    var bodyArgs = {
        search_session_id: parseInt(searchSessionId),
        user_session_id: userSessionId
    };
    if (offset) {
        bodyArgs.offset = parseInt(offset);
    }
    if (dir) {
        bodyArgs.dir = dir;
    }
    if (length) {
        if (isNaN(length)) {
            throw 'Length must be a number';
        }
        bodyArgs.length = parseInt(length);
    }
    if (fields) {
        bodyArgs.fields = fields.split(",");
    }
    var resBody = httpPost('server/search/events', null, bodyArgs);
    var events = xmlObjectToJSON(resBody);
    return events;
}

function getChartRequest(userSessionId, searchSessionId) {
    var bodyArgs = {
        search_session_id: parseInt(searchSessionId),
        user_session_id: userSessionId
    };
    bodyArgs.offset = 0;
    bodyArgs.length = 100;
    var resBody = httpPost('/server/search/chart_data', null, bodyArgs);
    var events = xmlObjectToJSON(resBody);
    return events;
}

function drilldown() {
    var result = drilldownRequest(args.sessionId, args.searchSessionId, args.startTime, args.endTime, args.lastDays);
    var entry = {
        Type: entryTypes.note,
        Contents: result,
        ContentsFormat: formats.json,
        ReadableContentsFormat: formats.text,
        HumanReadable: 'Success drilldown request'
    };
    return entry;
}

function drilldownRequest(userSessionId, searchSessionId, startTime, endTime, lastDays) {
    var bodyArgs = {
        search_session_id: parseInt(searchSessionId),
        user_session_id: userSessionId
    };
    if (lastDays) {
        if (isNaN(lastDays)) {
            throw 'LastDays must be a number';
        }
        var ld = parseInt(lastDays);
        var now = new Date();
        bodyArgs.end_time = now.toISOString();
        now.setTime(now.getTime() - ld * DAY_IN_MILLIS)
        bodyArgs.start_time = now.toISOString();
    } else if (startTime && endTime) {
        bodyArgs.end_time = endTime;
        bodyArgs.start_time = startTime;
    } else {
        throw 'Make sure lastDays is provided, or both startTime and endTime are provided'
    }
    var resBody = httpPost('server/search/drilldown', null, bodyArgs);
    return resBody;
}

function stopSearch() {
    stopSearchRequest(args.sessionId, args.searchSessionId);
    return {
        Type: entryTypes.note,
        ContentsFormat: formats.text,
        Contents: 'Search stopped successfully'
    };
}

function stopSearchRequest(userSessionId, searchSessionId) {
    var bodyArgs = {
        search_session_id: parseInt(searchSessionId),
        user_session_id: userSessionId
    };

    httpPost('server/search/stop', null, bodyArgs);
}

function fetchIncidents() {
    var userSessionId = login(params.credentials.identifier, params.credentials.password);
    var lastRun = getLastRun();

    var n = new Date();
    var endTime = n.toISOString();
    var startTime;
    var query;
    if (lastRun && lastRun.time && lastRun.time !== '') {
        startTime = lastRun.time;
    } else {
        n.setTime(n.getTime() - 1 * DAY_IN_MILLIS);
        startTime = n.toISOString();
    }
    if (params.eventsQuery){
        query = params.eventsQuery;
    }
    if (params.fields){
        var fields = params.fields;
        var discover_fields = true;
    } else {
        var fields = null;
        var discover_fields = false;
    }
    if (params.fetchlimit){
        var fetchlimit = params.fetchlimit;
    } else {
        var fetchlimit = 100;
    }
    var events = getSearchEventsRequest(userSessionId, query, 120000, startTime,
        endTime, discover_fields, null, null, false, null,
        null, null, fetchlimit, fields);

    var incidents = [];
    if(params.aggregate){
        var events_aggregate = { "Events" : events };
        var incident = incidentFromEvent(events_aggregate);
        incidents.push(incident);
    } else {
        for (var i = 0; i < events.length; i++) {
            var incident = incidentFromEvent(events[i]);
            incidents.push(incident);
        }
    }

    setLastRun({ time: endTime });
    return JSON.stringify(incidents);
}

switch(command) {
    case 'test-module':
        var userSessionId = login(params.credentials.identifier, params.credentials.password);
        logout(userSessionId);
        return 'ok';
    case 'fetch-incidents':
        return fetchIncidents();
    case 'as-search-events':
        var userSessionId = login(params.credentials.identifier, params.credentials.password);
        return getSearchEvents(userSessionId);
    case 'as-search':
        var userSessionId = login(params.credentials.identifier, params.credentials.password);
        var result = startSearchSession(userSessionId);
        return result;
    case 'as-status':
        var result = getSearchStatus();
        return result;
    case 'as-events':
        return getEvents();
    case 'as-close':
        var result = closeSession();
        logout(args.sessionId);
        return result;
    case 'as-stop':
        return stopSearch();
    case 'as-drilldown':
        return drilldown();
    default:
        throw 'Command ' + command + ' not exists';
}

function httpPost(path, queryObject, body) {
    var fullUrl = SERVER_URL + path;
    if (queryObject) {
        fullUrl += encodeToURLQuery(queryObject)
    }

    var req = {
        Method: 'POST',
        Headers: {
            'Content-Type' : ['application/json; charset=UTF-8'],
            'Accept': ['appliction/json']
        },
        Body: JSON.stringify(body)
    }
    var res = http(fullUrl, req, params.insecure, params.proxy);

    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        try {
            var resBody = JSON.parse(res.Body);
        } catch(e) {
            throw 'Request to ' + fullUrl + ' failed. StatusCode: ' + res.StatusCode + (res.Body !== '' ? '. Error: ' + res.Body : '');
        }
        var errTbl = resBody.errors;
        var errMessage = '';
        if (errTbl) {
            errTbl.forEach(function(err) {
                if(err.message) {
                    errMessage =  errMessage === '' ?  err.message : errMessage + ', ' + err.message;
                }
            });
        }
        throw 'Request to ' + fullUrl + ' failed. StatusCode: ' + res.StatusCode + '. Error: ' + errMessage;
    }
    try {
        return JSON.parse(res.Body);
    } catch(err){
        return res.Body;
    }
}

function parseXML(httpResponseBody) {
    var body = httpResponseBody.replace(/&#x.*?;/g, "");
    var parsed = JSON.parse(x2j(body));
    return parsed;
}

function parseBool(val) {
    return val === 'true' ? true : false;
}

function generateSearchSessionId() {
    var sessID = new Date().getTime();
    return sessID;
}

function parseArray(commaSepList) {
    return commaSepList.split(',');
}
function xmlObjectToJSON(xmlObject) {
    var context = [];
    if (xmlObject && xmlObject.fields && xmlObject.results) {
        var keys = [];
        var fields = xmlObject.fields;
        var entries = xmlObject.results;
        var isDateField = [];
        fields.forEach(function(field){
            if(field.name){
                keys.push(field.name.replace(/\s/g, '').replace(/^\_/,''));
                isDateField.push(field.type == 'date');
            }
        });
        entries.forEach(function(entry){
            if (entry.length == keys.length){
                var newEntry = {};
                for (var i = 0; i<  entry.length; i++){
                    if (isDateField[i] && !isNaN(entry[i])) {
                        var dateEntry = new Date(0);
                        dateEntry.setUTCSeconds(parseInt(entry[i]) / 1000);
                        entry[i] = dateEntry.toISOString();
                    }
                    newEntry[keys[i]] = entry[i];
                }
                context.push(newEntry);
            }
        });
    }
    return context;
}

function incidentFromEvent(event){
    var incident = {}
    //incident.labels = Object.keys(event);
    incident.rawJSON = JSON.stringify(event);
    var name = 'ArcSight Logger Incident';
    name = event.rowId ? name + ' ' + event.rowId : name;
    incident.name = name;
    return incident;
}
