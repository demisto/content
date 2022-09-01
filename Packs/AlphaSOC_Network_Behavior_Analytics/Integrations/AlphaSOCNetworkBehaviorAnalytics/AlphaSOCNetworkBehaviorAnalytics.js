var API_PATH_ALERTS = '/v1/alerts';

var SERVER = params.server.replace(/[\/]+$/, '');
var API_KEY = params.APIKey;

var INSECURE = params.insecure;
var PROXY = params.proxy;

var INCLUDE_POLICY = params.policy;
var SEVERITY = params.severity;

function sendRequest(requestUrl) {
    logInfo('Sending HTTP request to: ' + requestUrl);

    var response = http(
        requestUrl,
        {
            Method: 'GET',
            Headers: {
                Authorization: ['Basic ' + btoa(API_KEY + ':')],
                Accept: ['application/json']
            }
        },
        INSECURE,
        PROXY
    );

    var errorString = validateRequestResponse(requestUrl, response);
    if (errorString) {
        throw errorString;
    }

    try {
        return JSON.parse(response.Body);
    } catch (err) {
        throw 'Failed to parse JSON response: ' + response.Body;
    }
};

function validateRequestResponse(requestUrl, response) {
    if (!response) {
        return 'Error: Unexpected HTTP response\n\nRequest URL: ' + requestUrl;
    } else if (response.StatusCode < 200 || response.StatusCode >= 300) {
        var errorString = '';

        if (response.StatusCode === 401 || response.StatusCode === 403) {
            errorString = 'Error: Invalid API key\n';
        } else if (response.StatusCode === 429) {
            errorString = 'Error: Too many requests\n';
        }

        try {
            var body = JSON.parse(response.Body);
            if (body && body.message) {
                errorString += '\nMessage: ' + JSON.stringify(body.message);
            }
        } catch (err) {
            errorString += '\nCould not parse response body';
        }

        errorString += '\nRequest URL: ' + requestUrl + '\nStatus code: ' + response.StatusCode;
        return errorString;
    }

    return null;
}

function createAlertsURL(follow) {
    var severity = getSeverityThereshold();
    return SERVER + API_PATH_ALERTS + '?follow=' + follow + '&threats=all&minSeverity=' + severity;
}

function parseFollow() {
    var lastRun = getLastRun();
    return lastRun && lastRun.follow ? lastRun.follow : '0';
}

function saveFollow(follow) {
    if (follow) {
        setLastRun({ follow: follow });
    }
}

function testGetAlerts() {
    var response = sendRequest(createAlertsURL('0'));
    return response && response.alerts ? true : false;
}

function getAlerts(follow) {
    var response = sendRequest(createAlertsURL(follow));

    return {
        follow: response.follow,
        content: response.alerts,
        threats: response.threats
    }
}

function appendIncidentsFromAlert(incidents, alert, threats) {
    if (!threats || !alert || !alert.threats) {
        logInfo('Invalid alert format or empty threats definition');
        return;
    }

    var occurredTs = getOccurredTs(alert);
    for (var i = 0; i < alert.threats.length; i++) {
        var threatId = alert.threats[i];

        var threat = threats[threatId];
        if (!threat) {
            logInfo('Error: Invalid alert content. Definition for threat "' + threatId + '" not found');
            continue;
        }

        if (inScope(threat.severity, threat.policy)) {
            alert.policy = threat.policy === true ? true : false;

            incidents.push({
                'name': threat.title,
                'occurred': occurredTs,
                'severity': convertSeverity(threat.severity),
                'labels': getLabels(alert),
                'rawJSON': JSON.stringify(alert)
            });
        }
    }
}

function getOccurredTs(alert) {
    try {
        return alert.event.ts;
    } catch (exc) {
        return null;
    }
}

function getLabels(alert) {
    var labels = [];
    if (!alert) {
        return labels;
    }

    if (alert.eventType) {
        labels.push(createLabelEntry('eventType', alert.eventType));
    }

    if (alert.policy !== undefined && alert.policy !== null) {
        labels.push(createLabelEntry('policy', alert.policy));
    }

    if (alert.event) {
        var eventKeys = Object.keys(alert.event);
        for (var i = 0; i < eventKeys.length; i++) {
            var eventKey = eventKeys[i];
            if (eventKey !== 'ts') {
                labels.push(createLabelEntry(eventKey, alert.event[eventKey]));
            }
        }
    }

    if (alert.wisdom) {
        var wisdomKeys = Object.keys(alert.wisdom);
        for (var i = 0; i < wisdomKeys.length; i++) {
            var wisdomKey = wisdomKeys[i];
            labels.push(createLabelEntry('wisdom.' + wisdomKey, alert.wisdom[wisdomKey]));
        }
    }

    return labels;
}

function createLabelEntry(key, value) {
    return { 'type': key, 'value': String(value) };
}

function inScope(severity, policy) {
    var severityThereshold = getSeverityThereshold();
    if (!severity || severity < severityThereshold) {
        return false;
    }

    if (policy === true && !INCLUDE_POLICY) {
        return false;
    }

    return true;
}

function convertSeverity(severity) {
    var demistoSeverity = 0;

    try {
        demistoSeverity = severity === 1 ? .5 : severity - 1;
    } catch (exc) {
        demistoSeverity = 0;
    }

    return demistoSeverity < 0 || demistoSeverity > 4 ? 0 : demistoSeverity;
}

function getSeverityThereshold() {
    try {
        var severity = parseInt(SEVERITY);
    } catch (exc) {
        var severity = NaN;
    }

    if (isNaN(severity) || severity > 5) {
        throw 'Error: Invalid severity parameter. Please provide a number in range 0-5.';
    }

    return severity < 0 ? 0 : severity;
}

switch (command) {
    case 'test-module':
        try {
            getSeverityThereshold();
            return testGetAlerts() === true ? 'ok' : 'not ok';
        } catch (exc) {
            return String(exc);
        }
    case 'fetch-incidents':
        var follow = parseFollow();
        var alerts = getAlerts(follow);

        var incidents = [];
        if (alerts && alerts.content) {
            for (var i = 0; i < alerts.content.length; i++) {
                appendIncidentsFromAlert(incidents, alerts.content[i], alerts.threats);
            }
        }

        saveFollow(alerts.follow);
        return JSON.stringify(incidents);
}
