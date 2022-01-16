// remove '/' at the end of the url (if exists)
params.url = params.url.replace(/[\/]+$/, '');

var baseUrl = params.url;
if (params.port) {
    baseUrl = baseUrl + ':' + params.port;
}
var insecure = params.insecure;
var proxy = params.proxy;

// returns incId padded with '0's that is 15 length string. e.g. '82' -> '000000000000082'
var preperIncId = function (incId) {
    var res = '000000000000000' + incId;
    return res.substr(-15);
};

var createTableEntry = function (name, contents, context, headers) {
    return {
        // type
        Type: entryTypes.note,
         // contents
        ContentsFormat: formats.json,
        Contents: contents,
        // human-readable
        ReadableContentsFormat: formats.markdown,
        HumanReadable: tableToMarkdown(name, contents, headers),
        // context
        EntryContext: context
    };
};

// mutetor that removes all falsly fields
var filterEmptyFields = function(obj) {
    Object.keys(obj).forEach(function(key) {
        if (obj[key] === undefined || obj[key] === null) {
            delete obj[key];
        }
    });
};

var sendRequest = function(url, token, method, body) {

    var res = http(
        url,
        {
            Method: method || 'GET',
            Headers: {
                'Content-Type': ['application/json'],
                'Authorization': ['AR-JWT ' + token]
            },
            Body: body
        },
        insecure,
        proxy
    );

    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        logout(token);
        throw 'Request Failed'
            + '\nurl: ' + url
            + '\nStatus code: ' + res.StatusCode
            + '\nBody: ' + JSON.stringify(res);
    }

    return res;
};

var login = function() {
    var url = baseUrl + '/api/jwt/login';

    var body = {
        username: params.credentials.identifier,
        password: params.credentials.password
    };

    var res = http(
        url,
        {
            Method: 'POST',
            Headers: {
                'Content-Type': ['application/x-www-form-urlencoded']
            },
            Body: encodeToURLQuery(body).replace(/^\?/, '')
        },
        insecure,
        proxy
    );

    if (!res || res.StatusCode < 200 || res.StatusCode >= 300) {
        throw 'Request Failed'
            + '\nurl: ' + url
            + '\nStatus code: ' + res.StatusCode
            + '.\nBody: ' + JSON.stringify(res, null, 2);
    }

    // retrun the body which is tokenKey
    return res.Body;
};

var logout = function(token) {
    var url = baseUrl + '/api/jwt/logout/';
    sendRequest(url, token, 'POST');
};

var convertIncidentToTicket = function(incident) {
    return {
        ID: incident['Request ID'],
        Submitter: incident.Submitter,
        Status: incident.Status,
        Description: incident.Description,
        Source: incident['Reported Source'],
        Impact: incident.Impact,
        Urgency: incident.Urgency,
        Type: incident.Service_Type,
        Assignee: incident['Assigned To'],
        Email: incident['Internet E-mail'],
        Priority: incident.Priority,
        ServiceType: incident.Service_Type,
        ModifiedDate: incident['Modified Date']
    };
};

var createIncident = function(firstName, lastName, description, status, source, serviceType, impact, urgency, customFields) {
    var url = baseUrl + '/api/arsys/v1/entry/HPD:IncidentInterface_Create';
    var token = login();

    var body = {
       "values" : {
           "z1D_Action" : "CREATE",
     }
    };

    if (firstName) { body.values['First_Name'] = firstName; }
    if (lastName) { body.values['Last_Name'] = lastName; }
    if (description) { body.values['Description'] = description; }
    if (status) { body.values['Status'] = status; }
    if (source) { body.values['Reported Source'] = source; }
    if (serviceType) { body.values['Service_Type'] = serviceType; }
    if (impact) { body.values['Impact'] = impact; }
    if (urgency) { body.values['Urgency'] = urgency; }

    if (customFields) {
        var customFieldsArr = customFields.split(',');
        for (var i = 0; i < customFieldsArr.length; i++) {
            var equalIndex = customFieldsArr[i].indexOf('=');
            var key = customFieldsArr[i].substring(0, equalIndex);
            var value = customFieldsArr[i].substring(equalIndex + 1);
            body.values[key] = value;
        }
    }
    var res = sendRequest(url, token, "POST", JSON.stringify(body));
    // get created incident
    var incidentUrl = res && res.Headers && res.Headers.Location && res.Headers.Location[0];
    res = sendRequest(incidentUrl, token);
    logout(token);
    var incident = JSON.parse(res.Body).values;
    filterEmptyFields(incident);

    var context = {
        Ticket: convertIncidentToTicket(incident)
    };

    return createTableEntry("Incident created:",incident, context);
};

var getIncident = function(id, title) {
    var url = baseUrl + '/api/arsys/v1/entry/HPD:IncidentInterface/' + id;
    var token = login();
    var res = sendRequest(url, token);
    logout(token);
    var incident = JSON.parse(res.Body).values;
    filterEmptyFields(incident);

    var context = {
        'Ticket(val.ID && val.ID == obj.ID)': convertIncidentToTicket(incident)
    };
    return createTableEntry(title || "Incident:",incident, context);
};
var fetchIncidents = function(query, test_module=false) {
    var url = baseUrl + '/api/arsys/v1/entry/HPD:IncidentInterface/';
    if(query) {
        url += '?q=' + encodeURIComponent(query);
    }
    if (test_module) {
        url += '?limit=1'
    }
    var token = login();
    var res = sendRequest(url, token);
    logout(token);
    var body = JSON.parse(res.Body);

    var incidents = body.entries.map(function(b) { return b.values});
    incidents.forEach(filterEmptyFields);
    var context = {
        'Ticket(val.ID && val.ID == obj.ID)': incidents.map(convertIncidentToTicket)
    };
    return createTableEntry("Incidents:",incidents, context);
};

var updateIncident = function(incID, updateObject) {
    var url = baseUrl + '/api/arsys/v1/entry/HPD:IncidentInterface/' + incID + '|' + incID;
    var token = login();

    filterEmptyFields(updateObject);
    var body = {
       "values" : updateObject
    };

    sendRequest(url, token, "PUT", JSON.stringify(body));
    return getIncident(incID, 'Updated incident:');
};

var fetchIncidentsToDemisto = function() {
    var lastRun = getLastRun();
    nowDate = new Date();
    var now = nowDate.toISOString();
    if (!lastRun || !lastRun.value) {
        lastRun = {
            value: (new Date(nowDate.getTime() - 10*60*1000)).toISOString()
        };
    }
    logDebug("Last run value before starting to fetch: " + lastRun.value);
    var query =  "'Submit Date'>" + '"' + lastRun.value + '"';
    var url = baseUrl + '/api/arsys/v1/entry/HPD:IncidentInterface/' + '?q=' + encodeURIComponent(query);
    logDebug("This is the URL with the query for fetching the incidents: " + url);
    var token = login();
    var res = sendRequest(url, token);
    logout(token);
    var body = JSON.parse(res.Body);
    var incidents = []
    Object.keys(body.entries).forEach(function(key) {
        var incident = body.entries[key].values;
        var requestID = body.entries[key].values['Request ID'];
        incidents.push({
            'name': 'Remedy On-Demand incident ' + requestID,
            'labels': [
                {
                    'type': 'Ticket(val.ID && val.ID == obj.ID)',
                    'value': JSON.stringify(convertIncidentToTicket(incident)) // Ticket ID to be pushed to incident context
                }
            ],
            'rawJSON': JSON.stringify(incident)
        });
    });
    var now = new Date().toISOString();
    logDebug("Last run is set to: " + now);
    setLastRun({value: now});
    return JSON.stringify(incidents);
};

switch (command) {
    case 'test-module':
        fetchIncidents(query=null, test_module=true);
        return 'ok';
    case 'fetch-incidents':
        return fetchIncidentsToDemisto();
    case 'remedy-incident-create':
        return createIncident(
            args['first-name'],
            args['last-name'],
            args.description,
            args.status,
            args.source,
            args['service-type'],
            args.impact,
            args.urgency,
            args['custom-fields']
        );
    case 'remedy-get-incident':
        return getIncident(args.ID);
    case 'remedy-fetch-incidents':
        return fetchIncidents(args.query);
    case 'remedy-incident-update':
        return updateIncident(
            args.ID,
            {
                Description: args.description,
                Status: args.status,
                'Reported Source': args.source,
                'Service_Type': args['service-type'],
                Impact: args.impact,
                Urgency: args.urgency
            }
        );
}
