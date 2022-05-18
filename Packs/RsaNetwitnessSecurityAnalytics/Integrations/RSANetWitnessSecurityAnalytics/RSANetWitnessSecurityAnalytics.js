var url = params.url;
if (url.indexOf("https://") < 0) {
    url = 'https://' + url;
}
var username = params.username;
var password = params.password;
var proxy = params.proxy || false;
var COOKIE_PREFIX = 'RSA_SA_LICENSE=true; JSESSIONID=';

function FailedRequestError(message, url, query, reqBody, resBody) {
    return {
        message: message,
        url: url,
        query: query,
        reqBody: reqBody,
        resBody: resBody,
        toString: function() {
            var error = [
                message,
                'Request url: ' + url,
            ];

            if (query) {
                error.push('Request query: ' + JSON.stringify(query));
            }
            if (reqBody) {
                error.push('Request body:' + JSON.stringify(reqBody));
            }

            error.push('Response: ' + resBody);

            return error.join('\n');
        }
    };
}

function escapeRegExp(str) {
    return str.replace(/([.*+?^=!:${}()|\[\]\/\\])/g, "\\$1");
}

function replaceAll(str, find, replace) {
    return str.replace(new RegExp(escapeRegExp(find), 'g'), replace);
}

function login(url, username, password) {
    var fullUrl = url + '/j_spring_security_check';
    var res = http(
        fullUrl,
        {
            Method: 'POST',
            Headers: {
                'Origin': [url],
                'Content-Type': ['application/x-www-form-urlencoded'],
                'Referer': [url + '/login']
            },
            Body: 'j_username=' + username + '&j_password=' + password
        },
        true,
        proxy,
        true
    );

    if (res.StatusCode !== 302) {
        throw 'Failed to login with status [' + res.StatusCode + ']. Expected status 302. Check username or password. \nOriginal error: ' + res.Body;
    }

    var sessionId = null;
    res.Cookies.forEach(function(cookie) {
        if (cookie.Name === 'JSESSIONID') {
            sessionId = cookie.Value;
        }
    });

    try {
        getAvailableAssignees(sessionId);
    } catch(err) {
        throw 'Failed to login! Check username or password. Error: ' + err;
    }

    return sessionId;
}

function logout(url, sessionId) {
    var fullUrl = url + '/j_spring_security_logout';

    var res = http(
        fullUrl,
        {
            Method: 'GET',
            Headers: {
                'Origin': [url],
                'Content-Type': ['application/x-www-form-urlencoded'],
                'Cookie': [COOKIE_PREFIX + sessionId]
            }
        },
        true,
        proxy,
        true
    );

    if (res.StatusCode !== 302) {
        throw 'Failed to logout with status [' + res.StatusCode + ']. Expected status 302.\nOriginal error: ' + res.Body;
    }
}

function createQuery(args, defaultQuery) {
    args = args || {};
    defaultQuery = defaultQuery || {};
    var query = {};

    if (args.page || defaultQuery.page) {
        query.page = args.page || defaultQuery.page;
    }

    if (args.start || defaultQuery.start) {
        query.start = args.start || defaultQuery.start;
    }

    if (args.limit || defaultQuery.limit) {
        query.limit = args.limit || defaultQuery.limit;
    }

    if (args.sort || defaultQuery.sort) {
        query.sort = args.sort || defaultQuery.sort;
    }

    if (args.filter || defaultQuery.filter) {
        query.filter = args.filter || defaultQuery.filter;
    }

    return query;
}

function createQueryFromString(q) {
    if (!q.match(/(.*=.*&)*(.*=.*)/)) {
        throw 'invalid query. query must be of structure: key1=value1&key2=value2&keyN=valueN';
    }
    var query = replaceAll(q, '\"', '"')
        .split('&')
        .reduce(function(qArgs, nextArg) {
            var na = nextArg.split('=');
            var argKey = na[0];
            var argValue = na[1];
            qArgs[argKey] = argValue;
            return qArgs;
        }, {});

    return query;
}

var defaultIncidentFilter = {
    page: 1,
    start: 0,
    limit: 50,
    sort: JSON.stringify([
        {
            property:'created',
            direction: 'DESC'
        }
    ]),
    filter: JSON.stringify([
        {
            property: 'created',
            value: [
                851171984031, // year 1996
                new Date().getTime()
            ]
        }
    ])
};

function listIncidents(sessionId, args, incidentManagementId) {
    var fullUrl = url + '/ajax/incidents/' + incidentManagementId;
    var query = {};
    if (args.query) {
        query = createQueryFromString(args.query);
    } else {
        query = createQuery(args, defaultIncidentFilter);
    }

    fullUrl += encodeToURLQuery(query);

    var res = http(
        fullUrl,
        {
            Method: 'GET',
            Headers: {
                'Cookie': [COOKIE_PREFIX + sessionId]
            }
        },
        true,
        proxy
    );

    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        throw 'Failed to fetch incidents with status [' + res.StatusCode + ']. \nOriginal error: ' + res.Body;
    }

    try {
        incidentsRes = JSON.parse(res.Body);
        if (incidentsRes.success) {
            var incidents = incidentsRes.data;
            if (!args.loadAlerts) {
                return incidents;
            }

            // loading all the alerts which related to incident
            // we load the alerts and original alerts which contains the original events which the alert created from
            // this has performance impact
            for (var i = 0; i < incidents.length; i++) {
                var alerts = filterAlerts(sessionId, {
                    filter: JSON.stringify([
                        {
                            property: 'incidentId',
                            value: incidents[i].id
                        }
                    ])
                })
                incidents[i].alerts = [];
                alerts.forEach(function(alert) {
                    var originalAlert = getOriginalAlertById(sessionId, { alertId: alert.id });
                    incidents[i].alerts.push({
                        alert: alert,
                        orignalAlert: originalAlert
                    });
                });
            }

            return incidents;
        } else {
            throw FailedRequestError('Fetch incidents failed.', fullUrl, query, null, incidentsRes).toString();
        }
    } catch (err) {
        throw FailedRequestError('Unexpected error while fetching incidents. \nOriginal error: ' + err, fullUrl, query, null, res.Body).toString();
    }
}

function fetchIncidents(sessionId, args, incidentManagementId) {
    var now = new Date().getTime();
    var lastRun = getLastRun().lastRun || now - 1*60*1000; // last minute
    var lastRunNext = lastRun;

    var tillNow = now;
    var query = {
        loadAlerts: true,
        page: 1,
        start: 0,
        limit: 50,
        filter: JSON.stringify([{
            property: 'created',
            value: [
                lastRun,
                tillNow
            ]
        }])
    };

    // TODO handle paging. If number of incidents are more than 50, then we need to
    // fetch the next pages too.
    var lastIncidents = listIncidents(sessionId, query, incidentManagementId);
    var convertedIncidents = [];
    for (var i = 0; i < lastIncidents.length; i++) {
        var inc = lastIncidents[i];
        if (inc.created > lastRunNext) {
            // we get the last incident which created
            lastRunNext = inc.created + 1;
        }

        convertedIncidents.push({
            name: inc.id,
            occurred: new Date(inc.firstAlertTime),
            owner: inc.assignee ? inc.assignee.login : '',
            reason: inc.name,
            rawJSON: JSON.stringify(inc)
        });
    }

    setLastRun({ lastRun: lastRunNext });
    return JSON.stringify(convertedIncidents);
}

function getIncidentById(sessionId, args, incidentManagementId) {
    var fullUrl = [
        url,
        'ajax/incident',
        incidentManagementId,
        args.incidentId
    ].join('/');

    var res = http(
        fullUrl,
        {
            Method: 'GET',
            Headers: {
                'Cookie': [COOKIE_PREFIX + sessionId]
            }
        },
        true,
        proxy
    );

    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        throw 'Failed to get incident by id with status [' + res.StatusCode + ']. \nOriginal error: ' + res.Body;
    }

    try {
        incident = JSON.parse(res.Body);
        if (incident.success) {
            return incident.data;
        } else {
            throw FailedRequestError('Fetch incident by id failed.', fullUrl, null, null, incident).toString();
        }
    } catch (err) {
        throw FailedRequestError('Unexpected error while fetching incident by id. \nOriginal error: ' + err, fullUrl, null, null, res.Body).toString();
    }
}

var defaultComponentFilter = {
    page: 1,
    start: 0,
    limit: 1000,
    sort: replaceAll(JSON.stringify([
        {
            property: 'displayName',
            direction: 'ASC'
        }
    ]), '\"', '"')
};

function getComponents(sessionId, argz, types) {
    var fullUrl = url + '/common/devices';
    var query = {};
    if (argz.query) {
        query = createQueryFromString(argz.query);
    } else {
        query = createQuery(argz, defaultComponentFilter);
    }
    fullUrl += types ? '/types/' + types.join('/') : '';
    fullUrl += encodeToURLQuery(query);

    var res = http(
        fullUrl,
        {
            Method: 'GET',
            Headers: {
                'Cookie': [COOKIE_PREFIX + sessionId]
            }
        },
        true,
        proxy
    );

    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        throw 'Failed to fetch components with status [' + res.StatusCode + ']. \nOriginal error: ' + res.Body;
    }

    try {
        components = JSON.parse(res.Body);
        if (components.success) {
            return components.data;
        } else {
            throw FailedRequestError('Fetch components failed.', fullUrl, query, null, components).toString();
        }
    } catch (err) {
        throw FailedRequestError('Unexpected error when fetching components. \nOriginal error: ' + err, fullUrl, query, null, res.Body).toString();
    }
}

function getIncidentManagementId(sessionId) {
    var incidentManagement = getComponents(sessionId, {}, ['INCIDENT_MANAGEMENT']);

    if (!incidentManagement || incidentManagement.length === 0) {
        throw 'Failed to find RSA NetWitness INCIDENT_MANAGEMENT component/device: ' + JSON.stringify(incidentManagement);
    }

    return incidentManagement[0].id;
}

function createEventsQuery(args, predicateIds) {
    args = args || {};
    var query = {};

    query.deviceId = args.deviceId;
    query.collectionName = args.collectionName || '';
    query.predicateIds = predicateIds ? predicateIds.join(',') : '';
    query.timeRangeType = args.timeRangeType;
    query.startDate = args.startDate || '';
    query.endDate = args.endDate || '';
    query.lastCollectionTime = args.lastCollectionTime || '';
    query.mid1 = args.mid1 || 0;
    query.mid2 = args.mid2 || 0;
    query.investigationToken = args.investigationToken || '';
    query.page = args.page || 1;
    query.start = args.start || 0;
    query.limit = args.limit || 25;
    query.sort = args.sort
        ? replaceAll(args.sort, '\"', '"')
        : JSON.stringify([
            {
                property: 'id',
                direction: 'ASC'
            }
        ]);

    return query;
}
function getEvents(sessionId, args) {
    var predicateIds = [];
    if (args.filter) {
        var eventsViewHTML = getEventsViewHtml(sessionId);
        var csrfToken = extractCsrfTokenFromHTML(eventsViewHTML);
        var filters = args.filter.split(',');
        for (var i = 0; i < filters.length; i++) {
            var predicate = postEventsTransient(sessionId, filters[i], csrfToken);
            predicateIds.push(predicate);
        }
    }
    var query = createEventsQuery(args, predicateIds);
    var fullUrl = url + '/ajax/investigation/events' + encodeToURLQuery(query);

    var res = http(
        fullUrl,
        {
            Method: 'GET',
            Headers: {
                'Cookie': [COOKIE_PREFIX + sessionId]
            }
        },
        true,
        proxy
    );

    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        throw 'Failed to fetch events with status [' + res.StatusCode + ']. \nOriginal error: ' + res.Body;
    }

    try {
        events = JSON.parse(res.Body);
        if (events.success) {
            return events.data;
        } else {
            throw FailedRequestError('Fetch events failed.', fullUrl, query, null, events).toString();
        }
    } catch (err) {
        throw FailedRequestError('Unexpected while fetching events. \nOriginal error: ' + err, fullUrl, query, null, res.Body).toString();
    }
}
function postEventsTransient(sessionId, query, ctoken) {
    var fullUrl = url + '/predicates/transient';
    var body = {
        name: query,
        query: query,
        ctoken: ctoken
    };
    var res = http(
        fullUrl,
        {
            Method: 'POST',
            Headers: {
                'Cookie': [COOKIE_PREFIX + sessionId],
                'Content-Type': ['application/x-www-form-urlencoded']
            },
            Body: encodeToURLQuery(body).replace(/^\?/, '')
        },
        true,
        proxy
    );

    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        throw 'Failed to fetch events with status [' + res.StatusCode + ']. \nOriginal error: ' + res.Body;
    }

    try {
        transient = JSON.parse(res.Body);
        if (transient.success) {
            return transient.object;
        } else {
            throw FailedRequestError('Posting transient for events failed.', fullUrl, null, body, transient).toString();
        }
    } catch (err) {
        throw FailedRequestError('Unexpected while posting transient for events. \nOriginal error: ' + err, fullUrl, null, body, res.Body).toString();
    }
}

function getEventDetails(sessionId, args) {
    var fullUrl = url + '/investigation/reconstruct/event';
    var eventsViewHTML = getEventsViewHtml(sessionId);
    var csrfToken = extractCsrfTokenFromHTML(eventsViewHTML);

    var body = {
        deviceId: args.deviceId,
        collectionName: args.collectionName || '',
        eventId: args.eventId,
        contentType: 'AUTO',
        contentSide: 'REQUEST_AND_RESPONSE',
        contentLayout: 'TOP_TO_BOTTOM',
        packetOverride: -1,
        ctoken: csrfToken
    };
    var res = http(
        fullUrl,
        {
            Method: 'POST',
            Headers: {
                'Cookie': [COOKIE_PREFIX + sessionId],
                'Content-Type': ['application/x-www-form-urlencoded']
            },
            Body: encodeToURLQuery(body).replace(/^\?/, '')
        },
        true,
        proxy
    );

    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        throw 'Failed to fetch event with status [' + res.StatusCode + ']. \nOriginal error: ' + res.Body;
    }

    try {
        event = JSON.parse(res.Body);
        if (event.success) {
            var content = getEventContent(sessionId, event.data.uri);
            return {data: event.data, content: content};
        } else {
            throw FailedRequestError('Fetching event details', fullUrl, null, body, event).toString();
        }
    } catch (err) {
        throw FailedRequestError('Unexpected while fetching event details. \nOriginal error: ' + err, fullUrl, null, body, res.Body).toString();
    }
}

// Returns events/session data content.
function getEventContent(sessionId, urlSuffix) {
    var fullUrl = url + urlSuffix;
    var res = http(
        fullUrl,
        {
            Method: 'GET',
            Headers: {
                'Cookie': [COOKIE_PREFIX + sessionId]
            }
        },
        true,
        proxy
    );

    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        throw 'Failed to fetch event data (recontruction) with status [' + res.StatusCode + ']. \nOriginal error: ' + res.Body;
    }

    try {
        return res.Body;
    } catch (err) {
        throw FailedRequestError('Unexpected while fetching event data (recontruction). \nOriginal error: ' + err, fullUrl, query, null, res.Body).toString();
    }
}

var defaultAlertQuery = {
    page: 1,
    start: 0,
    limit: 100,
    sort: JSON.stringify([
        {
            property:'alert.timestamp',
            direction: 'DESC'
        }
    ]),
    filter: JSON.stringify([
        {
            property: 'alert.timestamp',
            value: [
                851171984031, // year 1996
                new Date().getTime()
            ]
        }
    ])
};
function filterAlerts(sessionId, args) {
    var query = createQuery(args, defaultAlertQuery);
    var fullUrl = [
        url,
        '/ajax/alerts/',
        incidentManagementId,
        encodeToURLQuery(query)
    ].join('');

    var res = http(
        fullUrl,
        {
            Method: 'GET',
            Headers: {
                'Cookie': [COOKIE_PREFIX + sessionId]
            }
        },
        true,
        proxy
    );

    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        throw 'Failed to fetch alerts with status [' + res.StatusCode + ']. \nOriginal error: ' + res.Body;
    }

    try {
        alerts = JSON.parse(res.Body);
        if (alerts.success) {
            return alerts.data;
        } else {
            throw FailedRequestError('Fetch alerts failed.', fullUrl, query, null, alerts).toString();
        }
    } catch (err) {
        throw FailedRequestError('Unexpected while fetching alerts. Original error:' + err, fullUrl, query, null, res.Body).toString();
    }
}

function getAlertById(sessionId, args) {
    var fullUrl = [
        url,
        'ajax/alerts',
        incidentManagementId,
        args.alertId
    ].join('/');

    var res = http(
        fullUrl,
        {
            Method: 'GET',
            Headers: {
                'Cookie': [COOKIE_PREFIX + sessionId]
            }
        },
        true,
        proxy
    );

    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        throw 'Failed to get events of alert with status [' + res.StatusCode + ']. \nOriginal error: ' + res.Body;
    }

    try {
        alert = JSON.parse(res.Body);
        if (alert.success) {
            return alert.data;
        } else {
            throw FailedRequestError('Fetch alert details failed.', fullUrl, query, null, alert).toString();
        }
    } catch (err) {
        throw FailedRequestError('Unexpected while fetching alert details. \nOriginal error: ' + err, fullUrl, null, null, res.Body).toString();
    }
}

function getOriginalAlertById(sessionId, args) {
    var fullUrl = [
        url,
        'ajax/alerts/originalalert',
        incidentManagementId,
        args.alertId
    ].join('/');

    var res = http(
        fullUrl,
        {
            Method: 'GET',
            Headers: {
                'Cookie': [COOKIE_PREFIX + sessionId]
            }
        },
        true,
        proxy
    );

    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        throw 'Failed to get events of alert with status [' + res.StatusCode + ']. \nOriginal error: ' + res.Body;
    }

    try {
        alert = JSON.parse(res.Body);
        if (alert.success) {
            return alert.data;
        } else {
            throw FailedRequestError('Fetch alert details failed.', fullUrl, query, null, alert).toString();
        }
    } catch (err) {
        throw FailedRequestError('Unexpected while fetching alert details. \nOriginal error: ' + err, fullUrl, null, null, res.Body).toString();
    }
}

function getAvailableAssignees(sessionId) {
    var fullUrl = url + '/ajax/incident/user/availableAssignees';

    var res = http(
        fullUrl,
        {
            Method: 'GET',
            Headers: {
                'Cookie': ['RSA_SA_LICENSE=true; SaneID=10.64.49.14-1456516139492605; s_pers=%20s_fid%3D0D47AAAFD2A1592B-3436DC4A7A7EB300%7C1531522908438%3B%20gpv_pn%3DMYTOOLSSTATIC%252FTOOLS%252FTHE%2520SQUARE%7C1468452708438%3B%20s_lv%3D1468450908454%7C1563058908454%3B%20s_lv_s%3DLess%2520than%25201%2520day%7C1468452708454%3B; s_vi=[CS]v1|2B6795DE050118E9-40001608C00050FA[CE]; s_fid=3D8DF632622AC544-1283F8DF4BA4E8DC; JSESSIONID=' + sessionId]
            }
        },
        true,
        proxy
    );

    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        throw 'Failed to fetch availabe assignees with status [' + res.StatusCode + ']. \nOriginal error: ' + res.Body;
    }

    try {
        availableAssignees = JSON.parse(res.Body);
        if (availableAssignees.success) {
            return availableAssignees.data;
        } else {
            throw FailedRequestError('Fetch available assignees failed.', fullUrl, null, null, availableAssignees).toString();
        }
    } catch (err) {
        throw FailedRequestError('Unexpected error while fetching available assignees. \nOriginal error: ' + err, fullUrl, null, null, res.Body).toString();
    }
}

function getEventsViewHtml(sessionId) {
    var fullUrl = url + '/investigation/events';

    var res = http(
        fullUrl,
        {
            Method: 'GET',
            Headers: {
                'Cookie': [COOKIE_PREFIX + sessionId]
            }
        },
        true,
        proxy
    );

    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        throw 'Failed to fetch CSRF token with status [' + res.StatusCode + ']. \nOriginal error: ' + res.Body;
    }

    return res.Body;
}

function extractCsrfTokenFromHTML(html) {
    var matched = html.match(/<meta name="csrf-token" content=".*"/);
    if (!matched) {
        throw 'CSRF token not found! Internal error in NetWitness. Response  body: \n' + html;
    }

    var csrfToken = replaceAll(matched[0].replace('<meta name="csrf-token" content=', ''), '"', '');
    return csrfToken;
}

function extractLoggedUserFromHTML(html) {
    var matchedLoggedUser = html.match(/name: Ext\.htmlDecode\(.*\)/);
    if (!matchedLoggedUser) {
        throw 'Failed to determine logged in user. Html: ' + html;
    }

    var name = matchedLoggedUser[0].replace('name: Ext.htmlDecode(\'', '').replace('\')', '');
    var user = {
        name: name
    };

    return user;
}

var DEFAULT_SEVERITY = "50";
function createAlert(sessionId, args, incidentManagementId, createdUser, csrfToken) {
    var eventListString = replaceAll(args.eventList, ' ', '');
    var fullUrl = [
        url,
        'ajax/alert/create',
        args.deviceId,
        eventListString,
        incidentManagementId + '',
        '?ctoken=' + csrfToken
    ].join('/');

    var body = {
        alertSummary: args.alertSummary,
        event_id_list: eventListString.split(','),
        severity: args.severity ? args.severity + '' : DEFAULT_SEVERITY,
        create_by_user: createdUser.name
    };

    var res = http(
        fullUrl,
        {
            Method: 'POST',
            Headers: {
                'Cookie': [COOKIE_PREFIX + sessionId],
                'Content-Type': ['application/json']
            },
            Body: JSON.stringify(body)
        },
        true,
        proxy
    );

    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        throw 'Failed to create new alert with status [' + res.StatusCode + ']. \nOriginal error: ' + res.Body;
    }

    try {
        var alertRes = JSON.parse(res.Body);
        if (alertRes.success) {
            return alertRes.data;
        } else {
            throw FailedRequestError('Failed to create alert.', fullUrl, null, body, alertRes).toString();
        }
    } catch (err) {
        throw FailedRequestError('Unexpected error while creating alert. \nOriginal error: ' + err, fullUrl, null, body, res.Body).toString();
    }
}

function createIncident(sessionId, args, incidentManagementId, availableAssignees) {
    var eventsViewHTML = getEventsViewHtml(sessionId);
    var csrfToken = extractCsrfTokenFromHTML(eventsViewHTML);
    var loggedUser = extractLoggedUserFromHTML(eventsViewHTML);
    // currently we extract only the name of the logged in user. But the all the user object is exist in the html.
    // it just will take more development time.
    // that is why we look for the user in availableAssigness
    availableAssignees.forEach(function(user) {
        if (user.name === loggedUser.name) {
            loggedUser = user;
        }
    });

    var newAlert = createAlert(sessionId, args, incidentManagementId, loggedUser, csrfToken);

    var fullUrl = [
        url,
        'ajax/incident/create',
        incidentManagementId + '',
        '?ctoken=' + csrfToken
    ].join('/');

    var newIncident = {
        name: args.name,
        summary: args.summary || '',
        priority: args.priority,
        createdBy: loggedUser.name,
        alert_id_list: [
            newAlert.id
        ]
    };

    var res = http(
        fullUrl,
        {
            Method: 'POST',
            Headers: {
                'Cookie': [COOKIE_PREFIX + sessionId],
                'Content-Type': ['application/json']
            },
            Body: JSON.stringify(newIncident)
        },
        true,
        proxy
    );

    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        throw 'Failed to create incident with status [' + res.StatusCode + ']\n.'
            + 'Request Body: ' + JSON.stringify(body) + '\n. Response Body: ' + res.Body;
    }

    try {
        var newIncidentRes = JSON.parse(res.Body);
        if (newIncidentRes.success) {
            newIncident.id = newIncidentRes.data.id;
            return newIncident;
        } else {
            throw FailedRequestError('Failed to create incident.', fullUrl, null, body, newIncidentRes).toString();
        }
    } catch (err) {
        throw FailedRequestError('Unexpected error while creating incident. \nOriginal error: ' + err, fullUrl, null, body, res.Body).toString();
    }
}

function addEventsToIncident(sessionId, args, incidentManagementId, availableAssignees) {
    var eventsViewHTML = getEventsViewHtml(sessionId);
    var csrfToken = extractCsrfTokenFromHTML(eventsViewHTML);
    var loggedUser = extractLoggedUserFromHTML(eventsViewHTML);
    // currently we extract only the name of the logged in user. But the all the user object is exist in the html.
    // it just will take more development time.
    // that is why we look for the user in availableAssigness
    availableAssignees.forEach(function(user) {
        if (user.name === loggedUser.name) {
            loggedUser = user;
        }
    });

    var newAlert = createAlert(sessionId, args, incidentManagementId, loggedUser, csrfToken);

    var fullUrl = [
        url,
        'ajax/incident/addToIncident',
        incidentManagementId + '',
        '?ctoken=' + csrfToken
    ].join('/');

    var reqBody = {
        alertIds: [
            newAlert.id
        ],
        incidentId: args.incidentId
    };

    var res = http(
        fullUrl,
        {
            Method: 'POST',
            Headers: {
                'Cookie': [COOKIE_PREFIX + sessionId],
                'Content-Type': ['application/json']
            },
            Body: JSON.stringify(reqBody)
        },
        true,
        proxy
    );

    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        throw 'Failed to add events to incident with status [' + res.StatusCode + ']\n.'
            + 'Request Body: ' + JSON.stringify(body) + '\n. Response Body: ' + res.Body;
    }

    try {
        var resObject = JSON.parse(res.Body);
        if (resObject.success) {
            return true;
        } else {
            throw FailedRequestError('Failed to add events to incident.', fullUrl, null, body, newIncidentRes).toString();
        }
    } catch (err) {
        throw FailedRequestError('Unexpected error while adding new events to incident. \nOriginal error: ' + err, fullUrl, null, body, res.Body).toString();
    }
}

function updateIncident(sessionId, args, incidentManagementId, availableAssignees) {
    var eventsViewHTML = getEventsViewHtml(sessionId);
    var csrfToken = extractCsrfTokenFromHTML(eventsViewHTML);
    var loggedUser = extractLoggedUserFromHTML(eventsViewHTML);
    // currently we extract only the name of the logged in user. But the all the user object is exist in the html.
    // it just will take more development time.
    // that is why we look for the user in availableAssigness
    availableAssignees.forEach(function(user) {
        if (user.name === loggedUser.name) {
            loggedUser = user;
        }
    });

    var fullUrl = [
        url,
        'ajax/incidents/update',
        incidentManagementId + '',
        '?ctoken=' + csrfToken
    ].join('/');

    var updatedIncident = {
        id_list: replaceAll(args.idList, ' ', '').split(','),
        attribute_map: {
            lastUpdatedByUser: loggedUser
        },
        benign_domain_list: []
    };
    if (args.name) {
        updatedIncident.attribute_map.name = args.name;
    }
    if (args.priority) {
        updatedIncident.attribute_map.priority = args.priority;
    }
    if (args.status) {
        updatedIncident.attribute_map.status = args.status;
    }
    if (args.summary) {
        updatedIncident.attribute_map.summary = args.summary;
    }
    if (args.comment) {
        updatedIncident.attribute_map.comment = args.comment;
    }
    if (args.assignee) {
        var assigneeUser = null;
        availableAssignees.forEach(function(user) {
            if (user.login === args.assignee) {
                assigneeUser = user;
            }
        });
        if (!assigneeUser) {
            throw 'assignee argument is invalid. No such [' + args.assignee + '] available assignee user exist';
        }
        updatedIncident.attribute_map.assignee = assigneeUser;
    }
    if (args.categories) {
        updatedIncident.attribute_map.categories = args.categories;
    }

    var res = http(
        fullUrl,
        {
            Method: 'POST',
            Headers: {
                'Cookie': [COOKIE_PREFIX + sessionId],
                'Content-Type': ['application/json']
            },
            Body: JSON.stringify(updatedIncident)
        },
        true,
        proxy
    );

    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        throw 'Failed to create incident with status [' + res.StatusCode + ']\n.'
            + 'Request Body: ' + JSON.stringify(updatedIncident) + '\n. Response Body: ' + res.Body;
    }

    try {
        var updateRes = JSON.parse(res.Body);
        if (updateRes.success) {
            return updateRes;
        } else {
            throw FailedRequestError('Failed to update incident.', fullUrl, null, updatedIncident, updateRes).toString();
        }
    } catch (err) {
        throw FailedRequestError('Failed to update incident.', fullUrl, null, updatedIncident, res.Body).toString();
    }
}

function makeUpperCase (o) {
    for (var key in o ) {
        if(o.hasOwnProperty(key)) {
            var newKey = key.charAt(0).toUpperCase() + key.slice(1);
            o[newKey] = o[key];
            delete o[key];
        }
    }
    return o;
}

function getIncidentObject(e) {
    return {
        "Id": e.id,
        "Name": e.name,
        "Status": e.status,
        "Priority": e.priority,
        "Summary": e.summary,
        "Assignee": e.assignee ? e.assignee.name : "",
        "CreatedBy": e.createdBy,
        "Created": convertTimestampToString(e.created),
        "FirstAlertTime": convertTimestampToString(e.firstAlertTime),
        "LastUpdatedByUserName": e.lastUpdatedByUserName,
        "RiskScore": e.riskScore,
        "AverageAlertRiskScore": e.averageAlertRiskScore,
        "Categories": e.categories,
        "AlertCount": e.alertCount
    };
}

function getAlert (alert) {
    return {
        "Id": alert.id,
        "Name": alert.name,
        "IncidentId": alert.incidentId,
        "Timestamp": convertTimestampToString(alert.timestamp),
        "HostSummary": alert.host_summary,
        "SignatureId": alert.signature_id,
        "Source": alert.source,
        "Type": alert.type,
        "RiskScore": alert.risk_score,
        "SourceCountry": alert.groupby_source_country,
        "DestinationCountry": alert.groupby_destination_country,
        "NumEvents": alert.numEvents,
        "SourceIp": alert.groupby_source_ip,
        "DestonationIp": alert.groupby_destination_ip,
        "DestonationPort": alert.groupby_destination_port
    };
}
function buildRetValListIncidents (incidets) {
    var md = [];
    var ctx = {"Netwitness.Incident":[]}
    if (!Array.isArray(incidets)) {
        incidets = [incidets]
    }
    incidets.forEach(function (e) {
        var toPush = getIncidentObject(e);
        md.push(toPush);
        ctx["Netwitness.Incident"].push(toPush);
    })
    return {Type: entryTypes.note, Contents: incidets, ContentsFormat: formats.json, HumanReadable: tableToMarkdown(command, md), ReadableContentsFormat: formats.markdown, EntryContext: ctx};
}

function buildRetValGetIncidentDetails (incident) {
    var md = [];
    var ctx = {"Netwitness.Incident":[]}
    var toPush = getIncidentObject(incident);
    md.push(toPush);
    ctx["Netwitness.Incident"].push(toPush);
    return {Type: entryTypes.note, Contents: incident, ContentsFormat: formats.json, HumanReadable: tableToMarkdown(command, md), ReadableContentsFormat: formats.markdown, EntryContext: ctx};
}

function buildRetValGetComponents (components) {
    var md = [];
    var ctx = {"Netwitness.Component":[]}
    if (!Array.isArray(components)) {
        components = [components]
    }
    components.forEach(function (e) {
        var toPush = {
            "Id": e.id,
            "DisplayName": e.displayName,
            "DeviceVersion": e.deviceVersion,
            "DisplayType": e.deviceType,
            "Host": e.host,
            "Port": e.port,
            "Validated": e.validated,
            "Licensed": e.licensed,
            "Username": e.username,
            "EnableSSL": e.enableSSL
        };
        md.push(toPush)
        ctx["Netwitness.Component"].push(toPush);
    })
    return {Type: entryTypes.note, Contents: components, ContentsFormat: formats.json, HumanReadable: tableToMarkdown(command, md), ReadableContentsFormat: formats.markdown, EntryContext:  ctx};
}

function buildRetValGetEvents (events) {
    var md = [];
    var ctx = {"Netwitness.Event":[]}
    if (!Array.isArray(events)) {
        events = [events]
    }
    events.forEach(function (event) {
        var toPush = {
            "Id": event.id,
            "Medium": event.medium,
            "Service": event.service,
            "Size": event.size
        }
        event["meta"].forEach(function (meta) {
            toPush["meta." + meta.name] = meta.value
        });
        md.push(toPush);
    });
    return {Type: entryTypes.note, Contents: events, ContentsFormat: formats.json, HumanReadable: tableToMarkdown(command, md), ReadableContentsFormat: formats.markdown};
}

function buildRetValGetEventDetails (event) {
    var md = [];
    var ctx = {"Netwitness.Event":[]};
    var data = event.data;
    var content = event.content;
    var toPush = {
        "EventId": data.eventId,
        "DeviceId": data.deviceId,
        "ReconstructedContentType": data.reconstructedContentType,
        "PacketsTotal": data.stats ? data.stats.packetsTotal : "",
        "PacketsProcessed": data.stats ? data.stats.packetsProcessed : ""
    };
    data.summaryAttributes.forEach(function (e) {
        toPush[e.name] = e.value
    });
    md.push(toPush);
    ctx["Netwitness.Event"].push(toPush);
    return {Type: entryTypes.note, Contents: event, ContentsFormat: formats.json, HumanReadable: tableToMarkdown(command, md), ReadableContentsFormat: formats.markdown, EntryContext:  ctx};
}

function buildRetValGetAlerts (alerts) {
    var md = [];
    var ctx = {"Netwitness.Alert":[]}
    if (!Array.isArray(alerts)) {
        alerts = [alerts]
    }
    alerts.forEach(function (e) {
        var toPush = getAlert(e);
        md.push(toPush);
        ctx["Netwitness.Alert"].push(toPush);
    })
    return {Type: entryTypes.note, Contents: alerts, ContentsFormat: formats.json, HumanReadable: tableToMarkdown(command, md), ReadableContentsFormat: formats.markdown, EntryContext: ctx};
}

function buildRetValGetAlert (alert) {
    var ctx = {"Netwitness.Alert":[]}
    var alertValue = getAlert(alert);
    var eventValue = [];
    alert.events.forEach(function (evnt) {
        eventValue.push(treeToFlattenObject(evnt));
    });
    var relatedLinksValue = alert.related_links;
    var hr = tableToMarkdown('Alerts',alertValue)  + tableToMarkdown('Events', eventValue)  + tableToMarkdown('Related Links', relatedLinksValue);
    ctx["Netwitness.Alert"].push(alertValue);
    return {Type: entryTypes.note, Contents: alert, ContentsFormat: formats.json, HumanReadable: hr, ReadableContentsFormat: formats.markdown, EntryContext: ctx};
}

function buildRetValGetAlertOrig (alertOrig) {
    var md = [];
    var ctx = {"Netwitness.Event": []}
    if(!alertOrig.events) {
        return {"ContentsFormat": formats["markdown"], "Type": entryTypes["error"], "Contents": "Received an error from NetWitness Please ensure that the referred alert Id exist in NetWitness"};
    }
    alertOrig.events.forEach(function (evnt) {
        for (var key in evnt) {
            if (key === 'time') {
                evnt[key] = convertTimestampToString(evnt[key]);
            }
        }
    });
    md = alertOrig.events;
    ctx["Netwitness.Event"] = alertOrig.events;
    return {Type: entryTypes.note, Contents: alertOrig, ContentsFormat: formats.json, HumanReadable: tableToMarkdown(command, md), ReadableContentsFormat: formats.markdown, EntryContext: ctx};
}

function buildRetValAvailableAssignees(availableAssignees) {
    var md = [];
    var ctx = {"Netwitness.Account":[]}
    if (!Array.isArray(availableAssignees)) {
        availableAssignees = [availableAssignees]
    }
    availableAssignees.forEach(function (e) {
        var toPush ={
            "Id": e.id,
            "Name": e.name,
            "Login": e.login,
            "EmailAddress": e.emailAddress
        };
        md.push(toPush);
        ctx["Netwitness.Account"].push(toPush);
    })
    return {Type: entryTypes.note, Contents: availableAssignees, ContentsFormat: formats.json, HumanReadable: tableToMarkdown(command, md), ReadableContentsFormat: formats.markdown, EntryContext:  ctx};
}

function buildRetValCreateIncident (newIncident) {
    var md = [];
    var ctx = {"Netwitness.Incident":[]}
    var toPush = {
        "Id": newIncident.id,
        "Name": newIncident.name,
        "Priority": newIncident.priority,
        "CreatedBy": newIncident.createdBy,
        "AlertIDList": newIncident.alertIdList
    };
    md.push(toPush);
    ctx["Netwitness.Incident"].push(toPush)
    results = {Type: entryTypes.note, Contents: newIncident, ContentsFormat: formats.json, HumanReadable: tableToMarkdown(command, md), ReadableContentsFormat: formats.markdown, EntryContext:  ctx};
}


// The command input arg holds the command sent from the user.
var sessionId = login(url, username, password);
var incidentManagementId = args.incidentManagementId || getIncidentManagementId(sessionId);
var results = false;
switch (command) {
    case 'fetch-incidents':
        results = fetchIncidents(sessionId, args, incidentManagementId);
        break;
    case 'test-module':
        results = 'ok';
        break;
    case 'nw-login':
        results = sessionId;
        break;
    case 'netwitness-im-list-incidents':
        var incidents = listIncidents(sessionId, args, incidentManagementId);
        results = buildRetValListIncidents(incidents);
        break;
    case 'netwitness-im-get-incident-details':
        var incident = getIncidentById(sessionId, args, incidentManagementId);
        results = buildRetValGetIncidentDetails(incident);
        break;
    case 'netwitness-im-get-components':
        var components = getComponents(sessionId, args);
        results = buildRetValGetComponents(components);
        break;
    case 'netwitness-im-get-events':
        var events = getEvents(sessionId, args);
        results = buildRetValGetEvents(events);
        break;
    case 'netwitness-im-get-event-details':
        event = getEventDetails(sessionId, args);
        results = buildRetValGetEventDetails(event);
        break;
    case 'netwitness-im-get-alerts':
        var alerts = filterAlerts(sessionId, args);
        results = buildRetValGetAlerts(alerts);
        break;
    case 'netwitness-im-get-alert-details':
        var alert = getAlertById(sessionId, args);
        results = buildRetValGetAlert(alert);
        break;
    case 'netwitness-im-get-alert-original':
        var alert = getOriginalAlertById(sessionId, args);
        results = buildRetValGetAlertOrig(alert);
        break;
    case 'netwitness-im-get-available-assignees':
        var availableAssignees = getAvailableAssignees(sessionId);
        results = buildRetValAvailableAssignees(availableAssignees);
        break;
    case 'netwitness-im-create-incident':
        var availableAssignees = getAvailableAssignees(sessionId);
        var newIncident = createIncident(sessionId, args, incidentManagementId, availableAssignees);
        results = buildRetValCreateIncident(newIncident);
        break;
    case 'netwitness-im-add-events-to-incident':
        var md = [];
        var availableAssignees = getAvailableAssignees(sessionId, args);
        var isSuccess = addEventsToIncident(sessionId, args, incidentManagementId, availableAssignees);
        md.push({ success: isSuccess })
        results = {Type: entryTypes.note, Contents: { success: isSuccess }, ContentsFormat: formats.json, HumanReadable: tableToMarkdown(command, md), ReadableContentsFormat: formats.markdown};
        break;
    case 'netwitness-im-update-incident':
        var availableAssignees = getAvailableAssignees(sessionId, args);
        var update_incident = updateIncident(sessionId, args, incidentManagementId, availableAssignees);
        if( update_incident.success != true) {
            results = {"ContentsFormat": formats["markdown"], "Type": entryTypes["error"], "Contents": "Didn't succed to update incident.\n" + tableToMarkdown("Data returned:", update_incident)};
        }
        else if (update_incident.success == true && update_incident.data < 1) {
            results = {"ContentsFormat": formats["markdown"], "Type": entryTypes["error"], "Contents": "Received an error from NetWitness Please ensure that the referred incidents exist in NetWitness.  Incidents count = " + update_incident.data};
        }
        else {
            results = {
                "ContentsFormat": formats["text"],
                "Type": entryTypes["note"],
                "Contents": "Incident updated successfully."
            };
        }
        break;
    default:
        // You can use args[argName] or args.argName to get a specific arg. args are strings.
        // You can use params[paramName] or params.paramName to get a specific params.
        // Params are of the type given in the integration page creation.
}

logout(url, sessionId);
return results;
