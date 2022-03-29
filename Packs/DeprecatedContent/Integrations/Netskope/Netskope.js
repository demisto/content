var SERVER_URL = params.url.replace(/[\/]+$/, '');
var BASE_URL = SERVER_URL + '/api/v1/';
var TOKEN = params.token;

function sendRequest(method, api, stringifyData) {
    var requestUrl = BASE_URL + api;
    var result = http(
        requestUrl,
        {
            Method: method,
            Headers: {
                'Content-Type': ['application/json'],
                'Accept': ['application/json']
            }
        },
        params.insecure,
        params.proxy
        );
    if (result.StatusCode < 200 && result.StatusCode > 299) {
        throw 'Failed to perform request ' + path + ', request status code: ' + result.StatusCode + ', body: ' + result.Body;
    }
    if (result.Body === '') {
        throw 'No content received.' + requestUrl + result;
    }
    var body;
    try {
        // if fetching incidents, stringify long numbers to not round down long ids, e.g:
        // "dlp_incident_id":3747385551915191779 --> "dlp_incident_id":"3747385551915191779"
        if (stringifyData) {
            stringifyBody = result.Body.replace(/([\[:])?(\d{11,})([,\}\]])/g, "$1\"$2\"$3");
            return JSON.parse(stringifyBody)
        }
        body = JSON.parse(result.Body);
    } catch (ex) {
        throw 'Error parsing reply - ' + result.Body + ' - ' + ex;
    }
    return body;
}

function normalizeTimestamp(timestamp) {
    return Date(timestamp);
}

function translateTimeperiod(timeperiod){
    var timeperiodTranslator = {
        'Last60Minutes': '3600',
        'Last24Hours': '86400',
        'Last7Days': '604800',
        'Last30Days': '2592000',
        'Last60Days': '5184000',
        'Last90Days': '7776000'
    };
    return timeperiodTranslator[timeperiod];
}

function translateMonthName(monthName) {
    var monthTranslator = {
        'january': 1,
        'february': 2,
        'march': 3,
        'april': 4,
        'may': 5,
        'june': 6,
        'july': 7,
        'august': 8,
        'september': 9,
        'october': 10,
        'november': 11,
        'december': 12
    };
    return monthTranslator[monthName];
}

/**
* convert string formatted time to timestamp.
* Note: Accept 2 string formats: "dd-mm-yyyyTHH:MM:SSZ" or "Month Day, Year HH:MM:SS".
* @param {string} strDate - string formatted array
* @return {string} timestamp
*/
function toTimestamp(strDate){
    // accept: 31-12-1999T14:35:20Z
    var dateTuple = strDate.match('^(\\d{2})-(\\d{2})-(\\d{4})T(\\d{2}):(\\d{2}):(\\d{2})Z$');
    var timestamp;
    if (dateTuple !== null) {
        // first element is the entire match, then the individual matches.
        // months in Date JS are an integer between 0 and 11.
        timestamp = new Date(dateTuple[3], dateTuple[2] - 1, dateTuple[1], dateTuple[4], dateTuple[5], dateTuple[6]);
        return timestamp.getTime()/1000;
    }

    // accept: December 31, 1999 14:35:20
    dateTuple = strDate.toLowerCase().match('^(january|february|march|april|may|june|july|august|september|october|november|december) (\\d{1,2}), (\\d{4}) (\\d{2}):(\\d{2}):(\\d{2})$');
    if (dateTuple !== null) {
        timestamp = new Date(dateTuple[3], translateMonthName(dateTuple[1]) - 1, dateTuple[2], dateTuple[4], dateTuple[5], dateTuple[6]);
        return timestamp.getTime()/1000;
    }
    return strDate;
}

function getAlerts(stringifyData) {
    var queryArgs = {
        token: TOKEN,
        type: encodeURIComponent(args.type)
    };
    if (args.starttime && args.endtime) {
        queryArgs.starttime = toTimestamp(args.starttime);
        queryArgs.endtime = toTimestamp(args.endtime);
        if (args.timeperiod) {
            queryArgs.timeperiod = translateTimeperiod(args.timeperiod);
        }
        if (args.query) {
            queryArgs.query = encodeURIComponent(args.query);
        }
    } else if (args.timeperiod) {
        queryArgs.timeperiod = translateTimeperiod(args.timeperiod);
        if (args.query) {
            queryArgs.query = encodeURIComponent(args.query);
        }
    } else {
        throw 'Not given enough arguments to filter events by.';
    }

    var cmdUrl = 'alerts' + encodeToURLQuery(queryArgs);
    logInfo('Getting/Fetching Netskope Alerts (to be incidents) with ' + String(cmdUrl));
    var result = sendRequest('GET', cmdUrl, stringifyData);
    return result;
}

function getAlertsCommand() {
    result = getAlerts(false)
    var retArray = [];
    result.data.forEach(function(arrayItem) {
        var id = arrayItem._id;
        var app =  arrayItem.app;
        var timestamp =  normalizeTimestamp(arrayItem.timestamp);
        var dlp_profile =  arrayItem.dlp_profile;
        var dlp_file =  arrayItem.dlp_file;
        var hostname =  arrayItem.hostname;
        var policy =  arrayItem.policy;
        retArray.push({'ID': id, 'App' : app, 'Timestamp' : timestamp, 'DLPProfile' : dlp_profile, 'DLPFile' : dlp_file, 'Hostname' : hostname, 'Policy' : policy});
    });
    var ec = {
        "Netskope.Alerts(val.ID && val.ID === obj.ID)" : retArray
    };
    headers = ['ID', 'Timestamp', 'DLPProfile', 'DLPFile', 'Hostname', 'Policy'];
    return {
        Type: entryTypes.note,
        ContentsFormat: formats.json,
        Contents: result.data,
        ReadableContensFormat: formats.markdown,
        HumanReadable: tableToMarkdown('Netskope Alerts', retArray, headers),
        EntryContext: ec
    };
}

function getEvents() {
    var queryArgs = {
        token: TOKEN,
        type: encodeURIComponent(args.type)
    };
    if (args.starttime && args.endtime) {
        queryArgs.starttime = toTimestamp(args.starttime);
        queryArgs.endtime = toTimestamp(args.endtime);
        if (args.timeperiod) {
            queryArgs.timeperiod = translateTimeperiod(args.timeperiod);
        }
        if (args.query) {
            queryArgs.query = encodeURIComponent(args.query);
        }
    } else if (args.timeperiod) {
        queryArgs.timeperiod = translateTimeperiod(args.timeperiod);
        if (args.query) {
            queryArgs.query = encodeURIComponent(args.query);
        }
    } else {
        throw 'Not given enough arguments to filter events by.';
    }

    var cmdUrl = 'events' + encodeToURLQuery(queryArgs);
    var result = sendRequest('GET', cmdUrl);
    var retArray = [];
    result.data.forEach(function(arrayItem) {
        var id = arrayItem._id;
        var app =  arrayItem.app;
        var timestamp = normalizeTimestamp(arrayItem.timestamp);
        var activity =  arrayItem.activity;
        var object =  arrayItem.object;
        var hostname =  arrayItem.hostname;
        var category =  arrayItem.category;
        var device_classification =  arrayItem.device_classification;
        var user =  arrayItem.user;
        var from_user =  arrayItem.from_user;
        var to_user =  arrayItem.to_user;
        var srcip =  arrayItem.srcip;
        var access_method =  arrayItem.access_method;
        var url =  arrayItem.url;
        retArray.push({'ID': id, 'App' : app, 'Timestamp' : timestamp, 'Activity' : activity, 'Object' : object, 'Hostname' : hostname, 'AppCategory' : category, 'DeviceClassification' : device_classification, 'User' : user, 'FromUser' : from_user, 'ToUser' : to_user, 'SourceIP' : srcip, 'AccessMethod' : access_method, 'URL' : url});
    });
    var ec = {
        "Netskope.Events(val.ID && val.ID === obj.ID)" : retArray
    };
    headers = ['ID', 'App', 'Timestamp', 'Activity', 'Object', 'Hostname', 'AppCategory', 'DeviceClassification', 'User',
               'FromUser', 'ToUser', 'SourceIP', 'AccessMethod', 'URL'];
    return {
        Type: entryTypes.note,
        ContentsFormat: formats.json,
        Contents: result.data,
        ReadableContensFormat: formats.markdown,
        HumanReadable: tableToMarkdown('Netskope Events', retArray, headers),
        EntryContext: ec
    };
}

function now() {
    return parseInt(new Date().getTime()/1000);
}

function fetchAlerts() {
    lastRun = getLastRun();
    last_run = parseInt(lastRun.lastTime);
    if (isNaN(last_run)) {
        last_run = now() - parseInt(translateTimeperiod(params.firstFetch));
    }

    args = {};
    args.type = "";
    args.starttime = last_run.toString();
    args.endtime = now().toString();
    alerts = getAlerts(true).data;
    var incidents = [];
    var latestIncidedentTimeString = null;
    var latestIncidedentTimeInt = null;
    if (typeof alerts !== 'undefined') {
        alerts.reverse();  // alerts are fetched in descending order, reversing to process older first
        for (var i = 0; i < alerts.length; i++) {
            item = alerts[i];
            incident = {};
            d = new Date(item.timestamp);
            incident.occurred = d.toISOString();
            incident.name = item.alert_type + " - " + item.alert_name;
            incident.rawJSON = JSON.stringify(item);
            incidents.push(incident);
            if (latestIncidedentTimeInt == null || parseInt(item.timestamp) > latestIncidedentTimeInt) {
                latestIncidedentTimeInt = parseInt(item.timestamp);
                latestIncidedentTimeString = item.timestamp
            }
            if (incidents.length >= Math.min(50, params.maxFetch)) {
                break;
            }
        }
    }
    var incidentsLimitReached = (incidents.length >= Math.min(50, params.maxFetch));
    lastTime = incidentsLimitReached ? latestIncidedentTimeString : args.endtime;
    lastRun = {'lastTime': lastTime};
    setLastRun(lastRun);
    logInfo('Netskope lastRun is: ' + String(args.endtime));
    return JSON.stringify(incidents);
}

switch (command) {
    case 'test-module':
        var queryArgs = {
            token: TOKEN,
            type: 'application',
            timeperiod: '3600',
            limit: '1'
        };
        var cmdUrl = 'events' + encodeToURLQuery(queryArgs);
        result = sendRequest('GET', cmdUrl);
        if (result.status != "error") {
            return 'ok';
        }
        return result;
    case 'fetch-incidents':
        return fetchAlerts();
    case 'netskope-events':
        return getEvents();
    case 'netskope-alerts':
        return getAlertsCommand();
}
