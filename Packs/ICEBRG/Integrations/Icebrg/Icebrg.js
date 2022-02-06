var auth = 'IBToken ' + params.token;
var sendRequest = function(method, api, endpoint, body) {
    if (api == 'Search') {
        var url = params.url_search;
    } else {
        var url = params.url_reports;
    }
    endpoint = endpoint ? endpoint : '';
    var requestUrl = url.replace(/[\/]+$/, '') + '/' + endpoint;
    if (api === 'Reports' && !endpoint) {
        requestUrl = requestUrl + body;
        var res = http(
            requestUrl,
            {
                Method: method,
                Headers: {
                    'Authorization': [auth],
                    'Content-Type': ['application/json']
                }
            },
            params.insecure,
            params.proxy
        );
    } else {
        var res = http(
            requestUrl,
            {
                Method: method,
                Headers: {
                    'Authorization': [auth],
                    'Content-Type': ['application/json']
                },
                Body: body ? JSON.stringify(body) : undefined
            },
            params.insecure,
            params.proxy
        );
    }

    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        throw 'Request Failed.\nStatus code: ' + res.StatusCode + '.\nBody: ' + JSON.stringify(res) + '.';
    }
    return JSON.parse(res.Body);
};

var responseToEntry = function (response, path, title) {
    var data=[];
    if (Array.isArray(response)) {
        resKeys = Object.keys(response[0]);
    } else {
        resKeys = Object.keys(response);
    }
    for (i = 0; i < resKeys.length; i++) {
        data.push({
            to : underscoreToCamelCase(resKeys[i]),
            from: resKeys[i]
        });
    }
    var translator = {
        contextPath: 'Icebrg.' + path,
        title: title,
        data: data
    };
    return createEntry(response, translator);
};

var uppercaseKeys = function(obj) {
    return {
        UserUuid: obj.user_uuid,
        Published: obj.published
    };
};

var fetchCommandIncidents = function(urlArgs) {

    incidents = [];
    var res = sendRequest('GET', 'Reports', undefined, urlArgs);
    if (res.reports) {
        res.reports.forEach(function(inc){
            if (inc.asset_count > 0) {
                inc['origin'] = 'Reports';
                var ind = reportIndicators(inc.uuid);
                var asset = reportAssets(inc.uuid);
                if (asset.EntryContext) {
                    inc['Assets'] = asset.EntryContext['Icebrg.ReportAssets'];
                }
                if (ind.EntryContext) {
                    inc['Indicators'] = ind.EntryContext['Icebrg.ReportIndicators'];
                }
                incidents.push({
                  name: 'Reports',
                  rawJSON: JSON.stringify(inc)
                });
            }
        });
    }
    return incidents;
};

var fetchIncidents = function() {

    var lastRun = getLastRun();
    nowDate = new Date();
    var now = nowDate.toISOString();
    if (!lastRun || !lastRun.value) {
        lastRun = {value: (new Date(nowDate.getTime() - 1*60*1000)).toISOString()};
    }

    var urlArgs = encodeToURLQuery({published_start : now});
    var incidents = fetchCommandIncidents(urlArgs);

    setLastRun({value: now});
    return JSON.stringify(incidents);
};

var reportAssets = function(uuid) {
    var endpt = uuid + '/assets';
    var response = sendRequest('GET', 'Assets', endpt);
    if (!response.assets || response.assets.length === 0) {
        return 'No assets'
    }
    return responseToEntry(response.assets, 'ReportAssets', 'Report Assets');
};

var reportIndicators = function(uuid) {
    var endpt = uuid + '/indicators';
    var response = sendRequest('GET', 'Reports', endpt);
    if (!response.indicators || response.indicators.length === 0) {
        return 'No indicators'
    }
    return responseToEntry(response.indicators, 'ReportIndicators', 'Report Indicators');
};

switch (command) {
    case 'test-module':
        sendRequest('GET', 'Reports', '', '');
        return 'ok';
    case 'fetch-incidents':
        return fetchIncidents();
    case 'icebrg-search-events':
        var response = sendRequest('POST', 'Search', undefined, args);
        delete response.aggregations;
        if (!args.query) {
            return 'No query given'
        }
        return responseToEntry(response, 'Events', 'Events');
    case 'icebrg-get-history':
        var response = sendRequest('GET', 'Search', 'history');
        for(i=0; i<response.history.length; i++) {
            response.history[i].UserId=response.user_id;
        }
        return responseToEntry(response.history, 'UserQueryHistory', 'History');
    case 'icebrg-saved-searches':
        var response = sendRequest('GET', 'Search', 'saved');
        if (response.saved_queries) {
            return 'No saved searches'
        }
        return responseToEntry(response, 'SavedSearches', 'Saved Searches');
    case 'icebrg-get-reports':
        var queryArgs = {};
        var argKeys = Object.keys(args);
        for(i=0; i<argKeys.length; i++) {
            queryArgs[argKeys[i]] = args[argKeys[i]];
        }
        var response = sendRequest('GET', 'Reports', undefined, encodeToURLQuery(queryArgs));
        for(i=0; i<response.reports.length; i++) {
            response.reports[i].publishes = easyDQ(response.reports[i], 'publishes', undefined, uppercaseKeys);
        }
        return responseToEntry(response.reports, 'Reports', 'Reports');
    case 'icebrg-get-report-indicators':
        return reportIndicators(args.report_uuid);
    case 'icebrg-get-report-assets':
        return reportAssets(args.report_uuid);
    default:
}
