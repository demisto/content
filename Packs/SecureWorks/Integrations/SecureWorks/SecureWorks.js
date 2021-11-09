var SERVER_URL = params.server.replace(/[\/]+$/, '') + '/api/ticket/v3/';
var EVENT_SOURCE_HEALTH_TYPE = "CTP_HEALTH";
var CATEGORIZATION_CLASS_HEALTH_TYPE = "Health";
var MAX_LIMIT = 500;
// The following is the designated field to mark fetched tickets with
var DIRTY_FIELD = 'customerMiscellaneous4';
var DIRTY_VALUE = 'MARKED';


function sendRequest(path, method, queryParams, body){
    var query = '';
    if(queryParams){
        query = encodeToURLQuery(queryParams);
    }

    var url = SERVER_URL.concat(path, query);

    var res = http(
        url,
        {
            Method: method ? method : 'GET',
            Headers: {
                'Authorization': [ 'APIKEY ' + params.credentials.identifier + ':' + params.credentials.password],
                'Content-Type': ['application/json'],
            },
            Body: body ? JSON.stringify(body) : body
        },
        params.insecure,
        params.proxy
    );
    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        throw 'Failed on request ' + url + ' , request status code: ' + res.StatusCode + ' and Body: ' + res.Body + '.';
    }
    return JSON.parse(res.Body);
}

function convertTicketDates(response){
    if(!(response instanceof Array)){
        response = [response];
    }

    response.forEach(function(element){
        element.dateCreated = new Date(element.dateCreated).toString();
        element.dateModified = element.dateModified ? new Date(element.dateModified).toString() : '';
        element.dateClosed = element.dateClosed ? new Date(element.dateClosed).toString() : '';
    });
}

function createTicketCommand(){
    var response = createTicket(args.clientRef,
    args.clientLocationRef,
    args.requestType,
    args.title,
    args.externalTicket,
    args.deviceRef,
    args.detail,
    args.pocContactRef,
    args.watchers,
    args.attachments,
    args.source,
    args.assignedGroupId,
    args.assignedTicket2,
    args.partner,
    args.vendor,
    args.riskAssessment,
    args.changeSlo,
    args.changeWindowStart,
    args.changeWindowEnd,
    args.impact,
    args.urgency,
    args.priority,
    args.customerMiscellaneous1,
    args.customerMiscellaneous2,
    args.customerMiscellaneous3,
    args.customerMiscellaneous4,
    args.categorizationClass,
    args.categorizationCategory,
    args.categorizationType,
    args.categorizationItem);

    if(!response || !response.ticketID){
        return 'No data returned';
    }

    var translator = [
        {to: 'ticketId', from: 'ticketID'},
        {to: 'CreationStatusCode', from: 'code'}
    ];

    var entry = {
        Type: entryTypes.note,
        Contents: response,
        ContentsFormat: formats.json
    };

    var translated = cleanObject(mapObjFunction(translator)(response));
    entry.ReadableContentsFormat = formats.markdown;
    entry.HumanReadable = tableToMarkdown('Secure works create ticket response' , translated, Object.keys(translated));
    entry.EntryContext = {
        'SecureWorks.Ticket(val.ticketId==obj.ticketId)': translated
    };

    return entry;
}

function createTicket(
    clientRef,
    clientLocationRef,
    requestType,
    title,
    externalTicket,
    deviceRef,
    detail,
    pocContactRef,
    watchers,
    attachments,
    source,
    assignedGroupId,
    assignedTicket2,
    partner,
    vendor,
    riskAssessment,
    changeSlo,
    changeWindowStart,
    changeWindowEnd,
    impact,
    urgency,
    priority,
    customerMiscellaneous1,
    customerMiscellaneous2,
    customerMiscellaneous3,
    customerMiscellaneous4,
    categorizationClass,
    categorizationCategory,
    categorizationType,
    categorizationItem){

    var ticketBody = {};

    if(clientRef){
        ticketBody.clientRef = clientRef;
    }

    if(clientLocationRef){
        ticketBody.clientLocationRef = clientLocationRef;
    }

    if(requestType){
        ticketBody.requestType = requestType;
    }

    if(title){
        ticketBody.title = title;
    }

    if(externalTicket){
        ticketBody.externalTicket = externalTicket;
    }

    if(deviceRef){
        ticketBody.deviceRef = deviceRef;
    }

    if(detail){
        ticketBody.detail = detail;
    }

    if(pocContactRef){
        ticketBody.pocContactRef = pocContactRef;
    }

    if(watchers){
        ticketBody.watchers = watchers;
    }

    if(attachments){
        ticketBody.attachments = attachments;
    }

    if(source){
        ticketBody.source = source;
    }

    if(assignedGroupId){
        ticketBody.assignedGroupId = assignedGroupId;
    }

    if(assignedTicket2){
        ticketBody.assignedTicket2 = assignedTicket2;
    }

    if(partner){
        ticketBody.partner = partner;
    }

    if(vendor){
        ticketBody.vendor = vendor;
    }

    if(riskAssessment){
        ticketBody.riskAssessment = riskAssessment;
    }

    if(changeSlo){
        ticketBody.changeSlo = changeSlo;
    }

    if(changeWindowStart){
        ticketBody.changeWindowStart = changeWindowStart;
    }

    if(changeWindowEnd){
        ticketBody.changeWindowEnd = changeWindowEnd;
    }

    if(impact){
        ticketBody.impact = impact;
    }

    if(urgency){
        ticketBody.urgency = urgency;
    }

    if(priority){
        ticketBody.priority = priority;
    }

    if(customerMiscellaneous1){
        ticketBody.customerMiscellaneous1 = customerMiscellaneous1;
    }

    if(customerMiscellaneous2){
        ticketBody.customerMiscellaneous2 = customerMiscellaneous2;
    }

    if(customerMiscellaneous3){
        ticketBody.customerMiscellaneous3 = customerMiscellaneous3;
    }

    if(customerMiscellaneous4){
        ticketBody.customerMiscellaneous4 = customerMiscellaneous4;
    }

    if(categorizationClass){
        ticketBody.categorizationClass = categorizationClass;
    }

    if(categorizationCategory){
        ticketBody.categorizationCategory = categorizationCategory;
    }

    if(categorizationType){
        ticketBody.categorizationType = categorizationType;
    }

    if(categorizationItem){
        ticketBody.categorizationItem = categorizationItem;
    }

    var response = sendRequest('tickets', 'POST', '', ticketBody);

    return response;
}

function updateTicketCommand(){
    var id = args['id'];
    var response = updateTicket(id,
                      args.externalTicketNum,
                      args.externalTicketNum2,
                      args.externalGroupName,
                      args.watchers,
                      args.vendor,
                      args.customerMiscellaneous1,
                      args.customerMiscellaneous2,
                      args.customerMiscellaneous3,
                      args.customerMiscellaneous4);

    if(!response){
        return 'No data returned';
    }

    var translator = [
        {to: 'UpdateStatusCode', from: 'code'},
        {to: 'ticketId', from: 'ticketID'}
    ];

    var entry = {
        Type: entryTypes.note,
        Contents: response,
        ContentsFormat: formats.json
    };

    var translated = cleanObject(mapObjFunction(translator)(response));
    entry.ReadableContentsFormat = formats.markdown;
    entry.HumanReadable = tableToMarkdown('Secure works update ticket response' , translated);
    entry.EntryContext = {
        'SecureWorks.Ticket(val.ticketId==obj.ticketId)': translated
    };

    return entry;
}

function updateTicket(ticketId,
                      externalTicketNum,
                      externalTicketNum2,
                      externalGroupName,
                      watchers,
                      vendor,
                      customerMiscellaneous1,
                      customerMiscellaneous2,
                      customerMiscellaneous3,
                      customerMiscellaneous4) {

    var updateBody = {};

    if(externalTicketNum){
        updateBody.externalTicketNum = externalTicketNum;
    }

    if(externalTicketNum2){
        updateBody.externalTicketNum2 = externalTicketNum2;
    }

    if(externalGroupName){
        updateBody.externalGroupName = externalGroupName;
    }

    if(watchers){
        updateBody.watchers = watchers;
    }

    if(vendor){
        updateBody.vendor = vendor;
    }

    if(customerMiscellaneous1){
        updateBody.customerMiscellaneous1 = customerMiscellaneous1;
    }

    if(customerMiscellaneous2){
        updateBody.customerMiscellaneous2 = customerMiscellaneous2;
    }

    if(customerMiscellaneous3){
        updateBody.customerMiscellaneous3 = customerMiscellaneous3;
    }

    if(customerMiscellaneous4){
        updateBody.customerMiscellaneous4 = customerMiscellaneous4;
    }

    var response = sendRequest('tickets/' + ticketId, 'POST', '', updateBody);

    return response;
}

function getTicketCountCommand(){
    var countObject = getTicketCount(args.ticketType);

    var translator = [
        {to: 'TicketCount', from: 'ticketCount'}
    ];

    var entry = {
        Type: entryTypes.note,
        Contents: countObject,
        ContentsFormat: formats.json
    };

    var translated = mapObjFunction(translator)(countObject);
    entry.ReadableContentsFormat = formats.markdown;
    entry.HumanReadable = tableToMarkdown('Secure works get ticket count response' , translated);
    entry.EntryContext = {
        'SecureWorks.TicketCount': countObject.ticketCount
    }

    return entry;
}

function getTicketCount(ticketType){
    var queryParams = {}

    if(ticketType){
        queryParams.ticketType = ticketType;
    }

    var response = sendRequest('tickets/count', 'POST', queryParams);

    return response;
}

function assignTicketCommand(){
    var id = args['id'];
    var response = assignTicket(id,
            args.worklog,
            args.riskAssessment,
            args.changeApproval);

    if(!response){
        return 'No data returned';
    }

    var data = response.assignTicketToSoc;

    var translator = [
        {to: 'AssignStatusCode', from: 'code'},
        {to: 'ticketId', from: 'ticketId'}
    ];

    var entry = {
        Type: entryTypes.note,
        Contents: data,
        ContentsFormat: formats.json
    };

    var translated = cleanObject(mapObjFunction(translator)(data));
    entry.ReadableContentsFormat = formats.markdown;
    entry.HumanReadable = tableToMarkdown('Secure works assign ticket response' , translated);
    entry.EntryContext = {
        'SecureWorks.Ticket(val.ticketId==obj.ticketId)': translated
    };

    return entry;
}

function assignTicket(id,
            worklog,
            riskAssessment,
            changeApproval){

    var assignBody = {};

    if(worklog){
        assignBody.worklog = worklog;
    }

    if(riskAssessment){
        assignBody.riskAssessment = riskAssessment;
    }

    if(changeApproval){
        assignBody.changeApproval = changeApproval;
    }

    var response = sendRequest('tickets/' + id + '/assign', 'POST', '', assignBody);

    return response;
}

function closeTicketCommand(){
    var id = args['id'];
    var response = closeTicket(id, args.worklogContent, args.closeCode);

    if(!response){
        return 'No data returned';
    }

    var translator = [
        {to: 'ClosureStatusCode', from: 'code'},
        {to: 'ticketId', from: 'ticketID'}
    ];

    var entry = {
        Type: entryTypes.note,
        Contents: response,
        ContentsFormat: formats.json
    };

    var translated = cleanObject(mapObjFunction(translator)(response));
    entry.ReadableContentsFormat = formats.markdown;
    entry.HumanReadable = tableToMarkdown('Secure works close ticket response' , translated);
    entry.EntryContext = {
        'SecureWorks.Ticket(val.ticketId==obj.ticketId)': translated
    };

    return entry;
}

function closeTicket(id,
        worklogContent,
        closeCode){

    var closeBody = {};

    if(worklogContent){
        closeBody.worklogContent = worklogContent;
    }

    if(closeCode){
        closeBody.closeCode = closeCode;
    }

    var response = sendRequest('tickets/' + id + '/close', 'POST', '', closeBody);

    return response;
}

function addTicketWorklogCommand(){
    var id = args['id'];
    var response = addTicketWorklog(id, args.content);

    if(!response){
        return 'No data returned';
    }

    var translator = [
        {to: 'WorklogAdditionStatusCode', from: 'code'},
        {to: 'ticketId', from: 'ticketId'}
    ];

    var entry = {
        Type: entryTypes.note,
        Contents: response,
        ContentsFormat: formats.json
    };

    var translated = cleanObject(mapObjFunction(translator)(response));
    entry.ReadableContentsFormat = formats.markdown;
    entry.HumanReadable = tableToMarkdown('Secure works add ticket worklog response' , translated);
    entry.EntryContext = {
        'SecureWorks.Ticket(val.ticketId==obj.ticketId)': translated
    };

    return entry;
}

function addTicketWorklog(id, content) {
    var worklogBody = {content: content};

    var response = sendRequest('tickets/' + id + '/worklogs', 'POST', '', worklogBody);

    return response;
}

function getTicketCommand() {
    var ticket = getTicket(args['id'], args.includeWorklogs);

    if(!ticket){
        return 'No data returned';
    }

    convertTicketDates(ticket);

    var translator = [
        {to: 'ID', from: 'ticketId'},
        {to: 'Subject', from: 'symptomDescription'},
        {to: 'Description', from: 'detailedDescription'},
        {to: 'Status', from: 'status'},
        {to: 'Created', from: 'dateCreated'},
        {to: 'Updated', from: 'dateModified'},
        {to: 'Closed', from: 'dateClosed'},
        {to: 'Priority', from: 'priority'},
        {to: 'Reference', from: 'externalTicketNum'},
        {to: 'Location', from: 'clientLocation.name'},
        {to: 'Categorization', from: 'categorizationClass'},
        {to: 'Device', from: 'devices.name'},
        {to: 'Assigned Employee', from: 'contact.name'},
        {to: 'Watchers', from: 'watchers'},
        {to: 'AttachmentInfo', from: 'attachmentInfo.name'},
        {to: 'Type', from: 'groupingType'},
    ];

    if(ticket.worklogs){
        convertTicketDates(ticket.worklogs);
        var worklogTranslator = [
            {to: 'Created', from: 'dateCreated'},
            {to: 'Description', from: 'description'},
            {to: 'Type', from: 'type'}
        ];
        var worklogsTranslated = cleanObject(mapObjFunction(worklogTranslator)(ticket.worklogs));
    }

    var entries = [];
    if(args.getAttachments === 'true'){
        entries = getTicketAttachmentsEntries(ticket);
    }

    var entry = {
        Type: entryTypes.note,
        Contents: ticket,
        ContentsFormat: formats.json
    };

    var translated = cleanObject(mapObjFunction(translator)(ticket));
    var md = tableToMarkdown('Secure works get ticket response', translated, Object.keys(translated));
    md += (worklogsTranslated && worklogsTranslated.length > 0) ? tableToMarkdown('Worklogs', worklogsTranslated) : '';
    entry.ReadableContentsFormat = formats.markdown;
    entry.HumanReadable = md,
    entry.EntryContext = {
        'SecureWorks.Ticket(val.ticketId==obj.ticketId)': ticket
    };

    entries.push(entry);

    return entries;
}

function getTicket(ticketId, includeWorklogs) {
    var queryParams = {};
    if(includeWorklogs){
        queryParams.includeWorklogs = includeWorklogs;
    }
    var response = sendRequest('tickets/' + ticketId, 'GET', queryParams);

    return response;
}


function getTicketAttachmentsEntries(ticket) {
    var entries = [];
    if(!ticket.attachmentInfo || ticket.attachmentInfo.length === 0){
        return entries;
    }

    ticket.attachmentInfo.forEach(function(attachment) {
        var response = sendRequest('tickets/' + ticket.ticketId + '/attachments/' + attachment.id);
        if(response && response.attachment){
            entry = {
                Type: entryTypes.file,
                FileID: saveFile(atob(response.attachment.content)),
                File: response.attachment.filename,
                Contents: response.attachment.filename
            };

            entries.push(entry);
        }
    });

    return entries;
}

function getTicketsIdsCommand() {
        var response = getTicketsIds(args.ticketType, args.limit, args.groupingType);

        if(!response || !response.ticketIds || response.ticketIds.length === 0){
            return 'No ids returned';
        }

        var translator = [
            {to: 'IDs', from: 'ticketIds'}
        ];

        var entry = {
            Type: entryTypes.note,
            Contents: response,
            ContentsFormat: formats.json
        };

        var translated = cleanObject(mapObjFunction(translator)(response));
        entry.ReadableContentsFormat = formats.markdown;
        entry.HumanReadable = tableToMarkdown('Secure works get tickets ids response' , translated);
        entry.EntryContext = {
          'SecureWorks.IDs': response.ticketIds
        };

        return entry;
    }

function getTicketsIds(ticketType, limit, groupingType) {
    var queryParams = {}

    if(ticketType){
        queryParams.ticketType = ticketType;
    }

    if(limit){
        queryParams.limit = limit;
    }

    if(groupingType){
        queryParams.groupingType = groupingType;
    }

    var response = sendRequest('tickets/ids', 'POST', queryParams);

    return response;
}

function getTicketsUpdatesCommand() {
    var tickets = getTicketsUpdates(
    args.acknowledge,
    args.limit,
    args.ticketType,
    args.worklogs,
    args.groupingType);

    if(!tickets || tickets.length == 0){
        return 'No results found';
    }

    convertTicketDates(tickets);

    var translator = [
        {to: 'ID', from: 'ticketId'},
        {to: 'Reference', from: 'externalTicketNum'},
        {to: 'Created', from: 'dateCreated'},
        {to: 'Status', from: 'status'},
        {to: 'Subject', from: 'symptomDescription'},
        {to: 'Devices', from: 'devices.name'},
        {to: 'Assigned Employee', from: 'contact.name'},
        {to: 'Updated', from: 'dateModified'},
        {to: 'Closed', from: 'dateClosed'},
    ];

    var entry = {
        Type: entryTypes.note,
        Contents: tickets,
        ContentsFormat: formats.json
    };

    var translated = cleanObject(mapObjFunction(translator)(tickets));
    entry.ReadableContentsFormat = formats.markdown;
    entry.HumanReadable = tableToMarkdown('Secure works get tickets updates response', translated, Object.keys(translated[0]));
    entry.EntryContext = {
        'SecureWorks.Ticket(val.ticketId==obj.ticketId)': tickets
    };

    return entry;
}

function getTicketsUpdates(acknowledge,
    limit,
    ticketType,
    worklogs,
    groupingType) {

    var queryParams = {};
    if(limit){
        queryParams.limit = limit;
    }

    if(ticketType){
        queryParams.ticketType = ticketType;
    }

    if(worklogs){
        queryParams.worklogs = worklogs;
    }

    if(groupingType){
        queryParams.groupingType = groupingType;
    }

    var response = sendRequest('tickets/updates', 'POST', queryParams);

    if(!response){
        return response;
    }

    var responseTickets = response.tickets;
    var tickets = [];
    var ticketVersionsObject = {
        ticketVersions: []
    };
    responseTickets.forEach(function(responseTicket){
        tickets.push(responseTicket);
        ticketVersionsObject.ticketVersions.push({
            ticketId: responseTicket.ticketId,
            version: responseTicket.version
        });
    });

    if(acknowledge === "true" && tickets.length > 0){
        acknowledgeTickets(ticketVersionsObject);
    }

    return tickets;
}

function acknowledgeTickets(tickets) {
    var response = sendRequest('tickets/acknowledge', 'POST', '', tickets);

    return response;
}

function getCloseCodesCommand(){
    var id = args['id'];
    var response = getCloseCodes(id);

    if(!response){
        return 'No results found';
    }

    response.ticketID = id;

    var translator = [
        {from: 'ticketID', to: 'ID' },
        {from: 'closeCodes', to: 'CloseCodes'} ];

    var entry = {
        Type: entryTypes.note,
        Contents: response,
        ContentsFormat: formats.json,
        ReadableContentsFormat: formats.markdown
    };

    var translated = cleanObject(mapObjFunction(translator)(response));

    entry.HumanReadable = tableToMarkdown('Secure works close codes response', translated);
    entry.EntryContext = {
        'SecureWorks.Ticket(val.ticketID==obj.ticketID)': response
    };

    return entry;
}

function getCloseCodes(ticketId){
    var response = sendRequest('tickets/' + ticketId + '/close-codes', 'GET');

    return response;
}

function markTicket(ticketId){
       var updateBody = {};
       updateBody[DIRTY_FIELD] = DIRTY_VALUE;

       sendRequest('tickets/' + ticketId, 'POST', '', updateBody);
}

function fetchIncidents(){
    var queryParams = {};
    if(params.ticketType){
        queryParams.ticketType = params.ticketType;
    }
    if(params.groupingType){
        queryParams.groupingType = params.groupingType;
    }
    if(params.worklogs){
        queryParams.worklogs = params.worklogs;
    }
    queryParams.limit = MAX_LIMIT;

    var getAttachments = params.attachments === 'true' ? true : false;

    if(!params.status || params.status.length == 0){
        throw 'Error! Cannot fetch tickets without a status';
    }

    var statuses = params.status.split(',');
    var tickets = [];
    var ticketVersionsObject = {
        ticketVersions: []
    };

    var responseTickets = getTicketsUpdates(false,
    queryParams.limit,
    queryParams.ticketType,
    queryParams.worklogs,
    queryParams.groupingType);

    var attachments = [];

    responseTickets.forEach(function(responseTicket){
        // Exclude health tickets
        var excludeHealthFilter = responseTicket.eventSource !== EVENT_SOURCE_HEALTH_TYPE &&
            responseTicket.categorizationClass !== CATEGORIZATION_CLASS_HEALTH_TYPE;
        // Exclude tickets that were marked using the designated field
        var excludeMarkedTickets = responseTicket[DIRTY_FIELD] !== DIRTY_VALUE;

        if(statuses.indexOf(responseTicket.status) !== -1 && excludeHealthFilter && excludeMarkedTickets){
            convertTicketDates(responseTicket);
            tickets.push(responseTicket);

            if(getAttachments){
                var attachmentEntries = getTicketAttachmentsEntries(responseTicket);
                attachments = attachmentEntries.map(function(entry){
                   return {
                       path: entry['FileID'],
                       name: entry['File']
                   }
                });
            }

            ticketVersionsObject.ticketVersions.push({
                ticketId: responseTicket.ticketId,
                version: responseTicket.version
            });

            // Mark the designated field, so it's excluded next time
            markTicket(responseTicket.ticketId);
        }
    });

    var incidents = [];
    // convert tickets to demisto incidents
    if (tickets.length > 0) {
        acknowledgeTickets(ticketVersionsObject);
        tickets.forEach(function(ticket){
            var severity;
            switch(ticket.priority){
                case 'LOW':
                    severity = 1;
                    break;
                case 'MEDIUM':
                    severity = 2;
                    break;
                case 'HIGH':
                    severity = 3;
                    break;
                case 'CRITICAL':
                    severity = 4;
                    break;
                default:
                    severity = 0;
                    break;
            }
            var incident = {
                name: 'Secureworks - Ticket - ' + ticket.ticketId,
                severity: severity,
                details: ticket.detailedDescription,
                occurred: new Date(ticket.dateCreated).toISOString(),
                attachment: attachments,
                rawJSON: JSON.stringify(ticket)
            };

            incidents.push(incident);
        });
    }

    return JSON.stringify(incidents);
}

var entry = {};
switch(command){
    case 'test-module':
        var updates = getTicketsUpdates();
        return  updates ? 'ok' : 'not ok';
    case 'fetch-incidents':
        return fetchIncidents();
    case 'secure-works-create-ticket':
        entry = createTicketCommand();
        break;
    case 'secure-works-update-ticket':
        entry = updateTicketCommand();
        break;
    case 'secure-works-close-ticket':
        entry = closeTicketCommand();
        break;
    case 'secure-works-add-worklogs-ticket':
        entry = addTicketWorklogCommand();
        break;
    case 'secure-works-get-ticket':
        entry = getTicketCommand();
        break;
    case 'secure-works-assign-ticket':
        entry = assignTicketCommand();
        break;
    case 'secure-works-get-tickets-updates':
        entry = getTicketsUpdatesCommand();
        break;
    case 'secure-works-get-close-codes':
        entry = getCloseCodesCommand();
        break;
    case 'secure-works-get-tickets-ids':
        entry = getTicketsIdsCommand();
        break;
    case 'secure-works-get-ticket-count':
        entry = getTicketCountCommand();
        break;
}

return entry;
