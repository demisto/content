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
    case 'hpsm-create-request':
        result = createRequest();
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
    var updateIncident = {
        [params.resourcename]: {
            Category: args.category,
            Description: [
                args.description
            ],
            Service: args.service,
            Title: args.title,
        }
    };
    updateIncident[params.resourcename][params.resourcekey] = args.incidentid
    if (args.impact) {
        updateIncident[params.resourcename]['Impact'] = args.impact;
    }
    if (args.urgency) {
        updateIncident[params.resourcename]['Urgency'] = args.urgency;
    }
    if (args.alertStatus) {
        updateIncident[params.resourcename]['AlertStatus'] = args.alertStatus;
    }
    if (args.area) {
        updateIncident[params.resourcename]['Area'] = args.area;
    }
    if (args.assignmentgroup) {
        updateIncident[params.resourcename]['AssignmentGroup'] = args.assignmentgroup;
    }
    if (args.affectedCI) {
        updateIncident[params.resourcename]['AffectedCI'] = args.affectedCI;
    }
    if (args.company) {
        updateIncident[params.resourcename]['Company'] = args.company;
    }
    if (args.category) {
        updateIncident[params.resourcename]['Category'] = args.category;
    }

    if (args.type) {
        updateIncident[params.resourcename]['Type'] = args.type;
    }
    if (args.phase) {
        updateIncident[params.resourcename]['Phase'] = args.phase;
    }
    if (args.status) {
        updateIncident[params.resourcename]['Status'] = args.status;
    }
    if (args.subarea) {
        updateIncident[params.resourcename]['Subarea'] = args.subarea;
    }
    if (args.contactmethod) {
        updateIncident[params.resourcename]['ContactMethod'] = args.contactmethod;
    }
    if (args.servicerecipient) {
        updateIncident[params.resourcename]['ServiceRecipient'] = args.servicerecipient;
    }
    if (args.affectedservice) {
        updateIncident[params.resourcename]['AffectedService'] = args.affectedservice;
    }
    if (args.servicecontact) {
        updateIncident[params.resourcename]['ServiceContact'] = args.servicecontact;
    }
    if (args.subcategory) {
        updateIncident[params.resourcename]['SubCategory'] = args.subcategory;
    }
    if (args.classification) {
        updateIncident[params.resourcename]['Classification'] = args.classification;
    }
    if (args.priority) {
        updateIncident[params.resourcename]['Priority'] = args.priority;
    }
    if (args.serviceprovidercompany) {
        updateIncident[params.resourcename]['ServiceProviderCompany'] = args.serviceprovidercompany;
    }
    if (args.updateactiontitle) {
        updateIncident[params.resourcename]['UpdateActionTitle'] = args.updateactiontitle;
    }
    if (args.updateactiondescription) {
        updateIncident[params.resourcename]['UpdateActionDescription'] = args.updateactiondescription;
    }
    if (args.serviceassociatedwith) {
        updateIncident[params.resourcename]['ServiceAssociatedWith'] = args.serviceassociatedwith;
    }
    if (args.callbackcontactname) {
        newIncident[params.resourcename]['CallbackContactName'] = args.callbackcontactname;
    }
    if (args.contactname) {
        newIncident[params.resourcename]['ContactName'] = args.contactname;
    }
    if (args.itemname) {
        newIncident[params.resourcename]['ItemName '] = args.itemname;
    }
    if (args.purpose) {
         newIncident[params.resourcename]['Purpose'] = args.purpose;
    }
    if (args.quantity) {
        newIncident[params.resourcename]['Quantity'] = args.quantity;
    }

    //throw JSON.stringify(updateIncident)
    var res = doPost('/'+params.resourcename+'/'+args.incidentid, updateIncident);
    var parsedRes = JSON.parse(res);
    if (parsedRes.ReturnCode !== 0) {
        throw 'Failed to create incident. Error Response: ' + res.Messages;
    }

    hrIncident = parsedRes[params.resourcename];

    var entryContext = {
        'HPSM.Incidents': [parsedRes[params.resourcename]],
        Ticket: [
            {
                ID: parsedRes[params.resourcename][params.resourcekey],
                Creator: parsedRes[params.resourcename]['OpenedBy'],
                Assignee: parsedRes[params.resourcename]['Assignee'],
                State: parsedRes[params.resourcename]['Status']
            }
        ]
    };
    return {
        Type: entryTypes.note,
        ContentsFormat: formats.json,
        Contents: parsedRes,

        ReadableContentsFormat: formats.markdown,
        HumanReadable: tableToMarkdown('Updated Incident ' + parsedRes[params.resourcename][params.resourcekey], hrIncident),

        EntryContext: entryContext
    };
}

function createIncident() {
    var newIncident = {
    [params.resourcename]: {
        Category: args.category,
        Description: [
            args.description
        ],
        Service: args.service,
        Title: args.title,
        }
    };

    if (args.impact) {
        newIncident[params.resourcename]['Impact'] = args.impact;
    }
    if (args.urgency) {
        newIncident[params.resourcename]['Urgency'] = args.urgency;
    }
    if (args.alertStatus) {
        newIncident[params.resourcename]['AlertStatus'] = args.alertStatus;
    }
    if (args.area) {
        newIncident[params.resourcename]['Area'] = args.area;
    }
    if (args.assignmentgroup) {
        newIncident[params.resourcename]['AssignmentGroup'] = args.assignmentgroup;
    }
    if (args.affectedCI) {
        newIncident[params.resourcename]['AffectedCI'] = args.affectedCI;
    }
    if (args.company) {
        newIncident[params.resourcename]['Company'] = args.company;
    }
    if (args.category) {
       newIncident[params.resourcename]['Category'] = args.category;
    }
    if (args.type) {
        newIncident[params.resourcename]['Type'] = args.type;
    }
    if (args.phase) {
        newIncident[params.resourcename]['Phase'] = args.phase;
    }
    if (args.status) {
        newIncident[params.resourcename]['Status'] = args.status;
    }
    if (args.subarea) {
        newIncident[params.resourcename]['Subarea'] = args.subarea;
    }
    if (args.contactmethod) {
        newIncident[params.resourcename]['ContactMethod'] = args.contactmethod;
    }
    if (args.servicerecipient) {
        newIncident[params.resourcename]['ServiceRecipient'] = args.servicerecipient;
    }
    if (args.affectedservice) {
        newIncident[params.resourcename]['AffectedService'] = args.affectedservice;
    }
    if (args.servicecontact) {
        newIncident[params.resourcename]['ServiceContact'] = args.servicecontact;
    }
    if (args.subcategory) {
        newIncident[params.resourcename]['SubCategory'] = args.subcategory;
    }
    if (args.classification) {
        newIncident[params.resourcename]['Classification'] = args.classification;
    }
    if (args.priority) {
        newIncident[params.resourcename]['Priority'] = args.priority;
    }
    if (args.serviceprovidercompany) {
        newIncident[params.resourcename]['ServiceProviderCompany'] = args.serviceprovidercompany;
    }
    if (args.updateactiontitle) {
        newIncident[params.resourcename]['UpdateActionTitle'] = args.updateactiontitle;
    }
    if (args.serviceassociatedwith) {
        newIncident[params.resourcename]['ServiceAssociatedWith'] = args.serviceassociatedwith;
    }
    if (args.callbackcontactname) {
        newIncident[params.resourcename]['CallbackContactName'] = args.callbackcontactname;
    }
    if (args.contactname) {
    newIncident[params.resourcename]['ContactName'] = args.contactname;
    }
    if (args.itemname) {
        newIncident[params.resourcename]['ItemName '] = args.itemname;
    }
    if (args.purpose) {
        newIncident[params.resourcename]['Purpose'] = args.purpose;
    }
    if (args.quantity) {
        newIncident[params.resourcename]['Quantity'] = args.quantity;
    }

    //throw JSON.stringify(newIncident)
    var res = doPost('/'+params.resourcename, newIncident);
    var parsedRes = JSON.parse(res);
    if (parsedRes.ReturnCode !== 0) {
        throw 'Failed to create incident. Error Response: ' + res.Messages;
    }

    hrIncident = parsedRes[params.resourcename];

    var entryContext = {
        'HPSM.Incidents': [parsedRes[params.resourcename]],
        Ticket: [
            {
                ID: parsedRes[params.resourcename][params.resourcekey],
                Creator: parsedRes[params.resourcename]['OpenedBy'],
                Assignee: parsedRes[params.resourcename]['Assignee'],
                State: parsedRes[params.resourcename]['Status']
            }
        ]
    };

    return {
        Type: entryTypes.note,
        ContentsFormat: formats.json,
        Contents: parsedRes,

        ReadableContentsFormat: formats.markdown,
        HumanReadable: tableToMarkdown('Created Incident ' + parsedRes[params.resourcename][params.resourcekey], hrIncident),

        EntryContext: entryContext
    };
}

function createRequest() {
    var newRequest = {
        [params.resourcename]: {
            Category: args.category,
            Purpose: [
                args.purpose
            ],
            Service: args.service,
            Title: args.title,
        }
    };

    if (args.callbackcontactname) {
        newRequest[params.resourcename]['CallbackContactName'] = args.callbackcontactname;
    }
    if (args.contactname) {
        newRequest[params.resourcename]['ContactName'] = args.contactname;
    }
    if (args.title) {
        newRequest[params.resourcename]['Title'] = args.title;
    }
    if (args.purpose) {
         newRequest[params.resourcename]['Purpose'] = args.purpose;
    }

    if (args.callbackcontactname == args.contactname) {
        requested_for = args.contactname;
    } else {
        requested_for = args.callbackcontactname;
    }
    newRequest[params.resourcename]['cartItems'] = [{ 'ItemName': args.title , 'Quantity': '1', 'RequestedFor': requested_for }];

    if (args.impact) {
        newRequest[params.resourcename]['Impact'] = args.impact;
    }
    if (args.urgency) {
        newRequest[params.resourcename]['Urgency'] = args.urgency;
    }
    if (args.alertStatus) {
        newRequest[params.resourcename]['AlertStatus'] = args.alertStatus;
    }
    if (args.area) {
        newRequest[params.resourcename]['Area'] = args.area;
    }
    if (args.assignmentgroup) {
        newRequest[params.resourcename]['AssignmentGroup'] = args.assignmentgroup;
    }
    if (args.affectedCI) {
        newRequest[params.resourcename]['AffectedCI'] = args.affectedCI;
    }
    if (args.company) {
        newRequest[params.resourcename]['Company'] = args.company;
    }
    if (args.category) {
        newRequest[params.resourcename]['Category'] = args.category;
    }
    if (args.type) {
        newRequest[params.resourcename]['Type'] = args.type;
    }
    if (args.phase) {
        newRequest[params.resourcename]['Phase'] = args.phase;
    }
    if (args.status) {
        newRequest[params.resourcename]['Status'] = args.status;
    }
    if (args.subarea) {
        newRequest[params.resourcename]['Subarea'] = args.subarea;
    }
    if (args.contactmethod) {
        newRequest[params.resourcename]['ContactMethod'] = args.contactmethod;
    }
    if (args.servicerecipient) {
        newRequest[params.resourcename]['ServiceRecipient'] = args.servicerecipient;
    }
    if (args.affectedservice) {
        newRequest[params.resourcename]['AffectedService'] = args.affectedservice;
    }
    if (args.servicecontact) {
        newRequest[params.resourcename]['ServiceContact'] = args.servicecontact;
    }
    if (args.subcategory) {
        newRequest[params.resourcename]['SubCategory'] = args.subcategory;
    }
    if (args.classification) {
        newRequest[params.resourcename]['Classification'] = args.classification;
    }
    if (args.priority) {
        newRequest[params.resourcename]['Priority'] = args.priority;
    }
    if (args.serviceprovidercompany) {
        newRequest[params.resourcename]['ServiceProviderCompany'] = args.serviceprovidercompany;
    }
    if (args.updateactiontitle) {
        newRequest[params.resourcename]['UpdateActionTitle'] = args.updateactiontitle;
    }
    if (args.serviceassociatedwith) {
        newRequest[params.resourcename]['ServiceAssociatedWith'] = args.serviceassociatedwith;
    }

    //throw JSON.stringify(newRequest)
    var res = doPost('/'+params.resourcename, newRequest);
    var parsedRes = JSON.parse(res);
    if (parsedRes.ReturnCode !== 0) {
        throw 'Failed to create incident. Error Response: ' + res.Messages;
    }

    hrIncident = parsedRes[params.resourcename];
    inc = parsedRes['Messages'][2];
    incident = inc.split('"');

    var srHPSM = {};
    var lstHPSM = [];

    srHPSM['ID'] = incident[1];
    srHPSM['CallbackType'] = parsedRes[params.resourcename]['CallbackType'];
    srHPSM['CallbackContactName'] = parsedRes[params.resourcename]['CallbackContactName'];
    srHPSM['Title'] = parsedRes[params.resourcename]['Title'];
    srHPSM['Purpose'] = parsedRes[params.resourcename]['Purpose'][0];
    srHPSM['ContactName'] = parsedRes[params.resourcename]['ContactName'];

    lstHPSM.push(srHPSM);

    var entryContext = {
        'HPSM.ServiceRequest': lstHPSM,
    };

    return {
        Type: entryTypes.note,
        ContentsFormat: formats.json,
        Contents: parsedRes,

        ReadableContentsFormat: formats.markdown,
        HumanReadable: tableToMarkdown('Created Service Request ', lstHPSM),

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
    var incidents = doGet('/'+params.resourcename, args.query);
    incidents = JSON.parse(incidents);

    var hrIncidents = [];
    var incidentIds = [];
    if (incidents.content && incidents.content.length > 0) {
        incidents.content.forEach(function(inc) {
            hrIncidents.push(inc[params.resourcename]);
            incidentIds.push(inc[params.resourcename][params.resourcekey]);
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
    var incident = doGet('/'+params.resourcename + '/' + args.incidentId);
    incident = JSON.parse(incident);

    hrIncident = incident[params.resourcename];
    var entryContext = {
        'HPSM.Incidents': [incident[params.resourcename]],
        Ticket: [
            {
                ID: incident[params.resourcename][params.resourcekey],
                Creator: incident[params.resourcename]['OpenedBy'],
                Assignee: incident[params.resourcename]['Assignee'],
                State: incident[params.resourcename]['Status']
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
                Connecion: ['Closed'],
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
                Connecion: ['Closed'],
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
