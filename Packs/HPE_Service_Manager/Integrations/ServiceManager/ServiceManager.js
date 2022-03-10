var url = params.url + '/SM/9/rest';

// handle '/' at the end of the url
if (url[url.length - 1] === '/') {
    url = url.substring(0, url.length - 1);
}

var token = Base64.encode(params.username.identifier + ':' + params.username.password);

var result;
// The command input arg holds the command sent from the user.
switch (command) {
    case 'test-module':
        listDevices();
        result = 'ok';
        break;
    case 'hpsm-create-incident':
        result = createIncident();
        break;
    case 'hpsm-update-incident':
        result = updateIncident();
        break;
    case 'hpsm-list-incidents':
        result = listIncidents();
        break;
    case 'hpsm-get-incident-by-id':
        result = getIncidentById();
        break;
    case 'hpsm-create-resource':
        result = createResource();
        break;
    case 'hpsm-update-resource':
        result = updateResource();
        break;
    case 'hpsm-list-resource':
        result = listResources();
        break;
    case 'hpsm-get-resource-by-id':
        result = getResourceById();
        break;
    case 'hpsm-list-devices':
        result = listDevices();
        break;
    case 'hpsm-get-device':
        result = getDeviceById();
        break;
    default:
}
return result;
function updateIncident() {
    var newIncident = {
        Incident: {
            Category: args.category,
            Description: [
                args.description
            ],
            Service: args.service,
            Title: args.title,
        }
    };
    if (args.customFields !== undefined){
        fields = JSON.parse(args.customFields);
        for (var field in fields) {
            newIncident['Incident'][field] = fields[field]
        }
    }
    if (args.impact) {
        newIncident.Incident.Impact = args.impact;
    }
    if (args.urgency) {
        newIncident.Incident.Urgency = args.urgency;
    }
    if (args.alertStatus) {
        newIncident.Incident.AlertStatus = args.alertStatus;
    }
    if (args.area) {
        newIncident.Incident.Area = args.area;
    }
    if (args.assignmentGroup) {
        newIncident.Incident.AssignmentGroup = args.assignmentGroup;
    }
    if (args.affectedCI) {
        newIncident.Incident.AffectedCI = args.affectedCI;
    }
    if (args.company) {
        newIncident.Incident.Company = args.company;
    }
    if (args.category) {
        newIncident.Incident.Category = args.category;
    }
    if (args.phase) {
        newIncident.Incident.Phase = args.phase;
    }
    if (args.status) {
        newIncident.Incident.Status = args.status;
    }
    if (args.subarea) {
        newIncident.Incident.Subarea = args.subarea;
    }
    var res = doPost('/incidents/'+args.incidentId, newIncident);
    var parsedRes = JSON.parse(res);
    if (parsedRes.ReturnCode !== 0) {
        throw 'Failed to update incident. Error Response: ' + res.Messages;
    }
    hrIncident = parsedRes.Incident;
    var entryContext = {
        'HPSM.Incidents': [parsedRes.Incident],
        Ticket: [
            {
                ID: parsedRes.Incident.IncidentID,
                Creator: parsedRes.Incident.OpenedBy,
                Assignee: parsedRes.Incident.Assignee,
                State: parsedRes.Incident.Status
            }
        ]
    };
    return {
        Type: entryTypes.note,
        ContentsFormat: formats.json,
        Contents: parsedRes,
        ReadableContentsFormat: formats.markdown,
        HumanReadable: tableToMarkdown('Updated Incident ' + parsedRes.Incident.IncidentID, hrIncident),
        EntryContext: entryContext
    };
} // queryToObject takes query of format field1=value1&field2=value2 and return query object like: { "field1": "value1", "field2": "value2" }
function createIncident() {
    var newIncident = {
        Incident: {
            Category: args.category,
            Description: [
                args.description
            ],
            Service: args.service,
            Title: args.title,
        }
    };

    if (args.customFields !== undefined){
        fields = JSON.parse(args.customFields);
        for (var field in fields) {
            newIncident['Incident'][field] = fields[field]
        }
    }

    if (args.impact) {
        newIncident.Incident.Impact = args.impact;
    }
    if (args.urgency) {
        newIncident.Incident.Urgency = args.urgency;
    }
    if (args.alertStatus) {
        newIncident.Incident.AlertStatus = args.alertStatus;
    }
    if (args.area) {
        newIncident.Incident.Area = args.area;
    }
    if (args.assignmentGroup) {
        newIncident.Incident.AssignmentGroup = args.assignmentGroup;
    }
    if (args.affectedCI) {
        newIncident.Incident.AffectedCI = args.affectedCI;
    }
    if (args.company) {
        newIncident.Incident.Company = args.company;
    }
    if (args.category) {
        newIncident.Incident.Category = args.category;
    }

    if (args.phase) {
        newIncident.Incident.Phase = args.phase;
    }
    if (args.status) {
        newIncident.Incident.Status = args.status;
    }
    if (args.subarea) {
        newIncident.Incident.Subarea = args.subarea;
    }

    var res = doPost('/incidents', newIncident);
    var parsedRes = JSON.parse(res);
    if (parsedRes.ReturnCode !== 0) {
        throw 'Failed to create incident. Error Response: ' + res.Messages;
    }

    hrIncident = parsedRes.Incident;

    var entryContext = {
        'HPSM.Incidents': [parsedRes.Incident],
        Ticket: [
            {
                ID: parsedRes.Incident.IncidentID,
                Creator: parsedRes.Incident.OpenedBy,
                Assignee: parsedRes.Incident.Assignee,
                State: parsedRes.Incident.Status
            }
        ]
    };
    return {
        Type: entryTypes.note,
        ContentsFormat: formats.json,
        Contents: parsedRes,

        ReadableContentsFormat: formats.markdown,
        HumanReadable: tableToMarkdown('Created Incident ' + parsedRes.Incident.IncidentID, hrIncident),

        EntryContext: entryContext
    };
}

// queryToObject takes query of format field1=value1&field2=value2 and return query object like: { "field1": "value1", "field2": "value2" }
function queryToObject(query) {
    if (!query) {
        return null;
    }

    var queryObj = {};
    var queryArr = query.split('&');
    queryArr.forEach(function(keyValuePair) {
        var a = keyValuePair.split('=');
        var key = a[0];
        var value = a[1];
        queryObj[key] = value;
    });

    return queryObj;
}

function listIncidents() {
    var incidents = doGet('/incidents', args.query);
    incidents = JSON.parse(incidents);

    var hrIncidents = [];
    var incidentIds = [];
    if (incidents.content && incidents.content.length > 0) {
        incidents.content.forEach(function(inc) {
            hrIncidents.push(inc.Incident);
            incidentIds.push(inc.Incident.IncidentID);
        });
    }

    var entryContext = {
        'HPSM.IncidentIDs': incidentIds
    };

    return {
        Type: entryTypes.note,
        ContentsFormat: formats.json,
        Contents: incidents,

        ReadableContentsFormat: formats.markdown,
        HumanReadable: tableToMarkdown('Incidents List', hrIncidents),

        EntryContext: entryContext
    };
}

function getIncidentById() {
    var incident = doGet('/incidents/' + args.incidentId);
    incident = JSON.parse(incident);

    hrIncident = incident.Incident;
    var entryContext = {
        'HPSM.Incidents': [incident.Incident],
        Ticket: [
            {
                ID: incident.Incident.IncidentID,
                Creator: incident.Incident.OpenedBy,
                Assignee: incident.Incident.Assignee,
                State: incident.Incident.Status
            }
        ]
    };
    return {
        Type: entryTypes.note,
        ContentsFormat: formats.json,
        Contents: incident,

        ReadableContentsFormat: formats.markdown,
        HumanReadable: tableToMarkdown('Incident ' + args.incidentId, hrIncident),

        EntryContext: entryContext
    };
}

function listDevices() {
    var devices = doGet('/devices', args.query);
    devices = JSON.parse(devices);

    var hrDevices = [];
    var deviceIds = [];
    if (devices.content && devices.content.length > 0) {
        devices.content.forEach(function(dev) {
            hrDevices.push(dev.Device);
            deviceIds.push(dev.Device.ConfigurationItem);
        });
    }

    var entryContext = {
        'HPSM.DeviceIDs': deviceIds
    };

    return {
        Type: entryTypes.note,
        ContentsFormat: formats.json,
        Contents: devices,

        ReadableContentsFormat: formats.markdown,
        HumanReadable: tableToMarkdown('Devices List', hrDevices),

        EntryContext: entryContext
    };
}
function updateResource() {
    var resourceName = args.resourceName;
    var newResource = {};
    newResource[resourceName] = {
            Category: args.category,
            Description: [
                args.description
            ],
            Service: args.service,
            Title: args.title,
        }

    if (args.customFields !== undefined){
        fields = JSON.parse(args.customFields);
        for (var field in fields) {
            newResource[resourceName][field] = fields[field]
        }
    }
    if (args.impact) {
        newResource[resourceName]['Impact'] = args.impact;
    }
    if (args.urgency) {
        newResource[resourceName]['Urgency'] = args.urgency;
    }
    if (args.alertStatus) {
        newResource[resourceName]['AlertStatus'] = args.alertStatus;
    }
    if (args.area) {
        newResource[resourceName]['Area'] = args.area;
    }
    if (args.assignmentGroup) {
        newResource[resourceName]['AssignmentGroup'] = args.assignmentGroup;
    }
    if (args.affectedCI) {
        newResource[resourceName]['AffectedCI'] = args.affectedCI;
    }
    if (args.company) {
        newResource[resourceName]['Company'] = args.company;
    }
    if (args.category) {
        newResource[resourceName]['Category'] = args.category;
    }
    if (args.phase) {
        newResource[resourceName]['Phase'] = args.phase;
    }
    if (args.status) {
        newResource[resourceName]['Status'] = args.status;
    }
    if (args.subarea) {
        newResource[resourceName]['Subarea'] = args.subarea;
    }
    var res = doPost('/'+resourceName+'/'+args.incidentId, newResource);
    var parsedRes = JSON.parse(res);
    if (parsedRes.ReturnCode !== 0) {
        throw 'Failed to update resource. Error Response: ' + res.Messages;
    }
    hrResource = parsedRes[resourceName];

    var entryContext = {
        'HPSM.Resources': [parsedRes[resourceName]],
        Ticket: [
            {
                ID: parsedRes[resourceName][args.resourceKey],
                Creator: parsedRes[resourceName]['OpenedBy'],
                Assignee: parsedRes[resourceName]['Assignee'],
                State: parsedRes[resourceName]['Status']
            }
        ]
    };
    return {
        Type: entryTypes.note,
        ContentsFormat: formats.json,
        Contents: parsedRes,
        ReadableContentsFormat: formats.markdown,
        HumanReadable: tableToMarkdown('Updated Resource ' + parsedRes[resourceName][args.resourceKey], hrResource),
        EntryContext: entryContext
    };
} // queryToObject takes query of format field1=value1&field2=value2 and return query object like: { "field1": "value1", "field2": "value2" }
function createResource() {
    var resourceName = args.resourceName;
    var newResource = {};
    newResource[resourceName] = {
            Category: args.category,
            Description: [
                args.description
            ],
            Service: args.service,
            Title: args.title,
        }
    if (args.customFields !== undefined){
        fields = JSON.parse(args.customFields);
        for (var field in fields) {
            newResource[resourceName][field] = fields[field]
        }
    }
    if (args.impact) {
        newResource[resourceName]['Impact'] = args.impact;
    }
    if (args.urgency) {
        newResource[resourceName]['Urgency'] = args.urgency;
    }
    if (args.alertStatus) {
        newResource[resourceName]['AlertStatus'] = args.alertStatus;
    }
    if (args.area) {
        newResource[resourceName]['Area'] = args.area;
    }
    if (args.assignmentGroup) {
        newResource[resourceName]['AssignmentGroup'] = args.assignmentGroup;
    }
    if (args.affectedCI) {
        newResource[resourceName]['AffectedCI'] = args.affectedCI;
    }
    if (args.company) {
        newResource[resourceName]['Company'] = args.company;
    }
    if (args.category) {
        newResource[resourceName]['Category'] = args.category;
    }
    if (args.phase) {
        newResource[resourceName]['Phase'] = args.phase;
    }
    if (args.status) {
        newResource[resourceName]['Status'] = args.status;
    }
    if (args.subarea) {
        newResource[resourceName]['Subarea'] = args.subarea;
    }
    var res = doPost('/'+resourceName, newResource);
    var parsedRes = JSON.parse(res);
    if (parsedRes.ReturnCode !== 0) {
        throw 'Failed to create resource. Error Response: ' + res.Messages;
    }
    hrResource = parsedRes[resourceName];

    var entryContext = {
        'HPSM.Resources': [parsedRes[resourceName]],
        Ticket: [
            {
                ID: parsedRes[resourceName][args.resourceKey],
                Creator: parsedRes[resourceName]['OpenedBy'],
                Assignee: parsedRes[resourceName]['Assignee'],
                State: parsedRes[resourceName]['Status']
            }
        ]
    };
    return {
        Type: entryTypes.note,
        ContentsFormat: formats.json,
        Contents: parsedRes,
        ReadableContentsFormat: formats.markdown,
        HumanReadable: tableToMarkdown('Created Resource ' + parsedRes[resourceName][args.resourceKey], hrResource),
        EntryContext: entryContext
    };
} // queryToObject takes query of format field1=value1&field2=value2 and return query object like: { "field1": "value1", "field2": "value2" }
function listResources() {
    var resourceName = args.resourceName;
    var incidents = doGet('/'+resourceName, args.query);
    incidents = JSON.parse(incidents);
    var hrIncidents = [];
    var incidentIds = [];
    if (incidents.content && incidents.content.length > 0) {
        incidents.content.forEach(function(inc) {
            hrIncidents.push(inc[resourceName]);
            incidentIds.push(inc[resourceName][args.resourceKey]);
        });
    }
    var entryContext = {
        'HPSM.ResourceIDs': incidentIds
    };
    return {
        Type: entryTypes.note,
        ContentsFormat: formats.json,
        Contents: incidents,
        ReadableContentsFormat: formats.markdown,
        HumanReadable: tableToMarkdown('Resources List', hrIncidents),
        EntryContext: entryContext
    };
}
function getResourceById() {
    var resourceName = args.resourceName;
    var resource = doGet('/'+resourceName+'/'+ args.resourceId);
    resource = JSON.parse(resource);
    hrResource = resource[resourceName];

    var entryContext = {
        'HPSM.Resources': [resource[resourceName]],
        Ticket: [
            {
                ID: resource[resourceName]['IncidentID'],
                Creator: resource[resourceName]['OpenedBy'],
                Assignee: resource[resourceName]['Assignee'],
                State: resource[resourceName]['Status']
            }
        ]
    };
    return {
        Type: entryTypes.note,
        ContentsFormat: formats.json,
        Contents: resource,
        ReadableContentsFormat: formats.markdown,
        HumanReadable: tableToMarkdown('Resource ' + args.resourceId, hrResource),
        EntryContext: entryContext
    };
}
function getDeviceById() {
    var device = doGet('/devices/' + args.configurationItem);
    device = JSON.parse(device);

    hrDevice = device.Device;
    var entryContext = {
        'HPSM.Devices': [device.Device],
    };
    return {
        Type: entryTypes.note,
        ContentsFormat: formats.json,
        Contents: device,

        ReadableContentsFormat: formats.markdown,
        HumanReadable: tableToMarkdown('Device ' + args.configurationItem, hrDevice),

        EntryContext: entryContext
    };
}

function doPost(queryPath, body) {
    return doRequest('POST', queryPath, body);
}

function doPut(queryPath, body) {
    return doRequest('PUT', queryPath, body);
}

function doRequest(method, queryPath, body) {
    var requestUrl = url + queryPath;
    var res = http(
        requestUrl,
        {
            Method: method,
            Headers: {
                Authorization: ['Basic ' + token],
                'Content-Type': ['application/json']
            },
            Body: JSON.stringify(body)
        },
        params.insecure,
        params.proxy
    );

    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        var parsedRes;
        try {
            parsedRes = JSON.parse(res.Body);
        } catch (err) {}

        if (res.Body && parsedRes && parsedRes.ReturnCode !== 0 && parsedRes.Messages) {
            throw method + ' Request Failed to ' + requestUrl + '.\nStatus code: ' + res.StatusCode + '.\nError from Service Manager: ' + parsedRes.Messages;
        }

        throw method + ' Request Failed to ' + requestUrl + '.\nStatus code: ' + res.StatusCode + '.\nBody: ' + JSON.stringify(res.Body) + '.';
    }

    return res.Body;
}

function doGet(queryPath, queryParams) {
    var requestUrl = url + queryPath;
    if (queryParams && typeof queryParams === 'string') {
        // in case query is a string, then we convert it obj and then encode it to URL query
        // we also convert every \" to " and after encoding URI, the encodeURI encodes " to %22. We decode it to its original form
        requestUrl += '?' + encodeURI(queryParams.replace(/\\"/g,'"')).replace(/%22/g,"\"");
    } else if (queryParams) {
        // if the query is object then we encode it
        requestUrl += encodeToURLQuery(queryParams);
    }

    var res = http(
        requestUrl,
        {
            Method: 'GET',
            Headers: {
                Authorization: ['Basic ' + token],
                'Content-Type': ['application/json']
            }
        },
        params.insecure,
        params.proxy
    );

    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        throw 'GET Request Failed to ' + requestUrl + '.\nStatus code: ' + res.StatusCode + '.\nBody: ' + JSON.stringify(res) + '.';
    }

    return res.Body;
}
