var cachedInfo = getIntegrationContext();
if (!cachedInfo) {
    cachedInfo = {users: {}, customFields: {}};
}
if (!cachedInfo.user) {
    cachedInfo.users = {};
}
if (!cachedInfo.customFields) {
    cachedInfo.customFields = {};
}
if (!cachedInfo.timestamp) {
    cachedInfo.timestamp = new Date().getTime();
} else {
    logDebug('cachedInfo.timestamp==' + cachedInfo.timestamp + '. now== ' + new Date().getTime());
    if (cachedInfo.timestamp + (1000 * 3600 * 24) < new Date().getTime()) {
        logInfo('Clearing Zendesk cache');
        cachedInfo.timestamp = new Date().getTime();
        cachedInfo.users = {};
        cachedInfo.customFields = {};
    }
}
var quoteMd = function(text) {
    var res = '';
    text.split('\n').forEach(function(line) {
        res +=  '>' + line + '\n';
    });
    return res;
};
var escapeMd = function(text) {
    return text.split('|').join('\\|');
};
var getTicketId = function() {
    var ticketId = args.id;
    if (!ticketId) {
        labels = dq(incidents[0],'labels');
        labels.forEach(function(label) {
            if (label.type == 'TicketId') {
                ticketId = label.value;
            }
        });
    }
    if (!ticketId) {
        throw 'Missing Zendesk ticket ID';
    }
    return ticketId;
};
var getAttachmentId = function() {
    return (args.id.indexOf(':') > -1) ? args.id.split(':')[0] : args.id;
};
var loadCustomFields = function() {
    resCusFields = sendRequest('GET', 'ticket_fields.json');
    var dicFields = {};
    var arrUsers = [];
    for (var i = 0; i < resCusFields.ticket_fields.length; i++) {
        if (resCusFields.ticket_fields[i].active) {
            dicFields['id_' + resCusFields.ticket_fields[i].id] = resCusFields.ticket_fields[i].title;
            dicFields['name_' + resCusFields.ticket_fields[i].title] = resCusFields.ticket_fields[i].id;
        }
    }
    cachedInfo.customFields = dicFields;
    setIntegrationContext(cachedInfo);
};
var getUserDetails = function(id) {
    if (!cachedInfo.users || !cachedInfo.users[id]) {
        var res = sendRequest('GET', 'users/' + id + '.json');
        cachedInfo.users[id] = res.user;
        setIntegrationContext(cachedInfo);
    }
    if (cachedInfo.users[id]) {
        return cachedInfo.users[id];
    } else {
        return null;
    }
};
var getOrganizationDetails = function(id) {
    var res = sendRequest('GET', 'organizations/' + id + '.json');
    return res.organization;
};
var getUserName = function(id) {
    var user = getUserDetails(id);
    if (user) {
        return cachedInfo.users[id].name + ' (' + cachedInfo.users[id].email + ')';
    } else {
        return 'N/A';
    }
};
var getCustomFieldName = function(id) {
    if (!cachedInfo.customFields || !cachedInfo.customFields[id]) {
        loadCustomFields();
    }
    return cachedInfo.customFields['id_' + id];
};
var getCustomFieldId = function(name) {
    if (!cachedInfo.customFields || !cachedInfo.customFields[name]) {
        loadCustomFields();
    }
    return cachedInfo.customFields['name_' + name];
};
var sendRequest = function(method, url, body, attr) {
    var requestUrl = params.url + "/api/v2/" + url + encodeToURLQuery(attr);
    var res;
    var headers = {
        'Content-Type': ['application/json']
    };
    res = http(
        requestUrl,
        {
            Method: method,
            Headers: headers,
            Username: params.username + '/token',
            Password: params.api,
            Body: body
        },
        params.insecure,
        params.proxy
        );
    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        throw 'Request Failed.\nStatus code: ' + res.StatusCode + '.\nBody: ' + JSON.stringify(res.Body) + '.';
    }
    try {
        return JSON.parse(res.Body);
    } catch (ex) {
        throw 'Error in parsing reply - ' + res.Body + ' - ' + ex;
    }
};
var createTicket = function() {
    var ec = {Ticket: []};
    var md = '## Zendesk tickets\n';
    var isPublic = (args.private === 'no');
    var body = {
            ticket: {
                comment: {
                    body: args.comment,
                    'public': isPublic
                }
            }
        };
    if (args.requester_email) {
        var reqRequester = sendRequest('GET', 'users/search.json', '', {query: args.requester_email});
        if (reqRequester.users.length > 0) {
            body.ticket.requester_id = reqRequester.users[0].id;
        } else {
            throw 'There is no such requester email';
        }
    }
    if (args.assignee_email) {
        var reqAssignee = sendRequest('GET', 'users/search.json', '', {query: args.assignee_email});
        if (reqAssignee.users.length > 0) {
            body.ticket.assignee_id = reqAssignee.users[0].id;
        } else {
            throw 'There is no such assignee email';
        }
    }
    if (args.custom_fields) {
        var arrCust = args.custom_fields.split(',');
        var dicCustStr = {};
        for (var i = 0; i < arrCust.length; i++) {
            var tmpKey = arrCust[i].split('=');
            dicCustStr[tmpKey[0]] = tmpKey[1];
        }
        var arrRes = [];
        for (var strKey in dicCustStr) {
            arrRes.push({
                id: getCustomFieldId(strKey),
                value: dicCustStr[strKey]
            });
        }
        body.ticket.custom_fields = arrRes;
    }
    var ticket = {};
    for (var key in args) {
        if (key !== 'comment' &&
            key !== 'private' &&
            key !== 'requester_email' &&
            key !== 'assignee_email' &&
            key !== 'custom_fields') {
            body.ticket[key] = args[key];
            ticket[key] = args[key];
        }
    }
    res = sendRequest('POST', 'tickets.json', JSON.stringify(body));
    md += 'The ticket has been successfully created with id ' + res.ticket.id + '.\n';
    ticket.id = res.ticket.id;
    ticket.vendor = 'Zendesk';
    ticket.description = args.body;
    ticket.subject = args.subject;
    ec.Ticket.push(ticket);
    return ( {ContentsFormat: formats.json, Type: entryTypes.note, Contents: res, HumanReadable: md, EntryContext: ec} );
};
var listTickets = function() {
    var searchQ;
    if (!args.query) {
        searchQ = 'type:ticket -status:solved -status:closed';
    } else {
        searchQ = 'type:ticket ' + args.query;
    }
    var att = {query: searchQ, sort_by: 'created_at', sort_order: 'desc'};
    res = sendRequest('GET', 'search.json', '', att);
    var ec = {Ticket: []};
    var md = '## Zendesk tickets\n';
    md += 'Id|Created|Subject|Status\n';
    md += '-|-|-|-|-\n';
    for (var i = 0; i <  res.results.length; i++) {
        ec.Ticket.push({
            id: res.results[i].id,
            description: res.results[i].description,
            subject: res.results[i].subject,
            vendor: 'Zendesk'
        });
        md += res.results[i].id + '|' + res.results[i].created_at + '|' + escapeMd(res.results[i].subject) + '|' + res.results[i].status + '\n';
    }
    return ( {ContentsFormat: formats.json, Type: entryTypes.note, Contents: res, HumanReadable: md, EntryContext: ec} );
};
var updateTicket = function() {
    var ticketId = getTicketId();
    var md = '## Zendesk tickets\n';
    var ec = {};
    var body = {ticket: {}};
    if (args.requester_email) {
        var reqRequester = sendRequest('GET', 'users/search.json', '', {query: args.requester_email});
        if (reqRequester.users.length > 0) {
            body.ticket.requester_id = reqRequester.users[0].id;
        } else {
            throw 'There is no such requester email';
        }
    }
    if (args.assignee_email) {
        var reqAssignee = sendRequest('GET', 'users/search.json', '', {query: args.assignee_email});
        if (reqAssignee.users.length > 0) {
            body.ticket.assignee_id = reqAssignee.users[0].id;
        } else {
            throw 'There is no such assignee email';
        }
    }
    if (args.custom_fields) {
        var arrCust = args.custom_fields.split(',');
        var dicCustStr = {};
        for (var i = 0; i < arrCust.length; i++) {
            var tmpKey = arrCust[i].split('=');
            dicCustStr[tmpKey[0]] = tmpKey[1];
        }
        var arrRes = [];
        for (strKey in dicCustStr) {
            arrRes.push({
                id: getCustomFieldId(strKey),
                value: dicCustStr[strKey]
            })
        }
        body.ticket.custom_fields = arrRes;
    }
    for (var key in args) {
        if (key !== 'id' &&
            key !== 'requester_email' &&
            key !== 'assignee_email' &&
            key !== 'custom_fields') {
            body.ticket[key] = args[key];
            ec['Ticket(val.id == ' + ticketId + ').' + key] = args[key];
        }
    }
    res = sendRequest('PUT', 'tickets/' + ticketId + '.json', JSON.stringify(body));
    md += 'Ticket number ' + ticketId + ' has been updated successfully.\n';
    return ( {'ContentsFormat': formats.json, 'Type': entryTypes.note, 'Contents': res, "HumanReadable": md} );
};
var addComment = function() {
    var ticketId = getTicketId();
    var md = '## Zendesk tickets\n';
    var isPublic = (args.private === 'no') ? true : false;
    var comment = args.comment;
    if (args.addFooter == 'yes') {
        comment += '\n\n---------\nPosted using Demisto-Zendesk integration';
    }
    var body = {
            ticket: {
                comment: {
                    body: comment.split('\\n').join('\n'),
                    'public': isPublic
                }
            }
        };
    res = sendRequest('PUT', 'tickets/' + ticketId + '.json', JSON.stringify(body));
    md += 'Comment added successfully.\n';
    return ( {'ContentsFormat': formats.json, 'Type': entryTypes.note, 'Contents': res, "HumanReadable": md} );
};
var addUser = function() {
    var check_if_user_exists = (args.check_if_user_exists == 'True');
    var requests_suffix = check_if_user_exists ? 'users.json' : 'users/create_or_update.json';
    var body = {
            user: {
                name: args.name,
                email: args.email
            }
    };
    res = sendRequest('POST', requests_suffix, JSON.stringify(body));
    md = 'Zendesk user added successfuly - ' + args.name + ' (' + args.email + ')\n';
    return ( {'ContentsFormat': formats.json, 'Type': entryTypes.note, 'Contents': res, "HumanReadable": md} );
};
var addMinutes = function(date, minutes) {
        return new Date(date.getTime() + minutes*60000);
};
var getNowTime = function(minutesOffset) {
        var time = new Date();
        time = addMinutes(time,time.getTimezoneOffset());
        time = (minutesOffset) ? addMinutes(time,minutesOffset) : time;
        var month = "0" + (time.getMonth()+1);
        var day = "0" + time.getDate();
        var hours = "0" + time.getHours();
        var minutes = "0" + time.getMinutes();
        var seconds = "0" + time.getSeconds();
        var dateOld = time.getFullYear()+'-'+month.substr(-2)+'-'+day.substr(-2);
        var timeOld = hours.substr(-2) + ':' + minutes.substr(-2) + ':' + seconds.substr(-2);
        sertime = dateOld + "T" + timeOld + 'Z';
        return sertime;
};
var getTicketDetails = function() {
    var ticketId = getTicketId();
    var resDetails = sendRequest('GET', 'tickets/' + ticketId + '.json');
    var md = '### Zendesk ticket #' + resDetails.ticket.id + " - " + resDetails.ticket.subject + "\n";
    var ec = {}
    var usersEc = {}
    var org = {};
    var newContext = {};
    md += 'Requester: __' + getUserName(resDetails.ticket.requester_id) + '__\n';
    usersEc[resDetails.ticket.requester_id]=getUserName(resDetails.ticket.requester_id);
    if (resDetails.ticket.organization_id) {
        org = getOrganizationDetails(resDetails.ticket.organization_id);
        var tags = (org.tags && org.tags.length > 0) ? ' (' + org.tags.join(', ') + ')' : '';
        md += 'Organization: __' + org.name + '__' + tags +'\n';
    }
    md += 'Created time: __' + resDetails.ticket.created_at + '__\n';
    md += 'Priority: __' + resDetails.ticket.priority + '__\n';
    md += 'Status: __' + resDetails.ticket.status + '__\n';
    if (resDetails.ticket.assignee_id) {
        md += 'Assignee: __' + getUserName(resDetails.ticket.assignee_id) + '__\n';
        usersEc[resDetails.ticket.assignee_id]=getUserName(resDetails.ticket.assignee_id);
    }
    if (resDetails.ticket.recipient) {
        md += 'Recipients: __' + resDetails.ticket.recipient + '__\n';
    }
    md += "#### Description\n";
    md += quoteMd(resDetails.ticket.description) + "\n";
    var fieldsMd = '';
    var fieldsEc = {};
    for (var i = 0; i < resDetails.ticket.custom_fields.length; i++) {
        if (resDetails.ticket.custom_fields[i].value) {
            fieldsMd += "- __" + getCustomFieldName(resDetails.ticket.custom_fields[i].id) + "__: " + resDetails.ticket.custom_fields[i].value + "\n";
            fieldsEc[resDetails.ticket.custom_fields[i].id] = getCustomFieldName(resDetails.ticket.custom_fields[i].id)
        }
    }
    if (fieldsMd) {
        md += "#### Custom fields\n";
        md += fieldsMd;
    }
    newContext.id = resDetails.ticket.id;
    newContext.subject = resDetails.ticket.subject;
    newContext.created_at = resDetails.ticket.created_at;
    newContext.description = resDetails.ticket.description;
    newContext.priority = resDetails.ticket.priority;
    newContext.status = resDetails.ticket.status;
    newContext.attachments = [];
    resComments = sendRequest('GET', 'tickets/' + ticketId + '/comments.json');
    if (resComments.comments[0].attachments.length>0) {
        md += '#### Attachments\n';
        resComments.comments[0].attachments.forEach(function(attachment) {
            md += '- ' +  attachment.id.toString() + ': ' + attachment.file_name + '\n';
            newContext.attachments.push({id: attachment.id.toString(), filename: attachment.file_name});
        });
    }
    // starting at 1, as the first comment is actually the ticket description
    for (var i = resComments.comments.length - 1; i > 0; i--) {
        var userName = getUserName(resComments.comments[i].author_id)
        if (resComments.comments[i].public) {
            md += '##### Public comment #' + (i+1) + ' ' + resComments.comments[i].created_at + ' by ' + userName + '\n';
        } else {
            md += '##### Private comment #' + (i+1) + ' ' + resComments.comments[i].created_at + ' by ' + userName + '\n';
        }
        md += quoteMd(resComments.comments[i].body) + '\n\n';
        if (resComments.comments[i].attachments.length > 0) {
            md += '- Attachments\n';
            resComments.comments[i].attachments.forEach(function(attachment) {
                md += '   - ' +  attachment.id.toString() + ': ' + attachment.file_name + '\n';
                newContext.attachments.push({id: attachment.id, filename: attachment.file_name});
            });
        }
    }
    context = dq(invContext, 'Ticket(val.id == ' + ticketId + ').id');
    if (context) {
        ec['Ticket(val.id == ' + ticketId + ')'] = newContext;
    } else {
        ec.Ticket = newContext;
    }
    var res = {
        TicketDetails: resDetails,
        TicketComments: resComments,
        Users: usersEc,
        Organization: org,
        CustomFields: fieldsEc
    }
    return({ContentsFormat: formats.json, Type: entryTypes.note, Contents: res, HumanReadable: md, EntryContext: ec})
};
var getArticle = function() {
    var locale = args.locale || 'en-us';
    var url = 'help_center/' + locale + '/articles/' + args.articleID + '.json';
    res = sendRequest('GET', url);
    return ( {ContentsFormat: formats.html, Type: entryTypes.note, Contents: res.article.body} );
}
var getAttachment = function() {
    var attachmentId = getAttachmentId();
    var res = sendRequest('GET', 'attachments/' + attachmentId + '.json');
    var attachBin = http(res.attachment.content_url,{
                Method: 'GET',
                Username: params.username + '/token',
                Password: params.api,
                SaveToFile: true
            },
            params.insecure,
            params.proxy);
    return ({Type: 3, FileID: attachBin.Path, File: res.attachment.file_name, Contents: res.attachment.file_name});
};
var listAgents = function() {
    res = sendRequest('GET', 'users.json?role[]=agent&role[]=admin');
    var md = '## Zendesk user details\n';
    var ec = {ZendeskUsers: []};
    md += 'Id|Name|Email|Role|Time Zone\n';
    md += '---|---|---|---|---\n';
    for (var i = 0; i < res.users.length; i++) {
        md += res.users[i].id + '|';
        md += res.users[i].name + '|';
        md += res.users[i].email + '|';
        md += res.users[i].role + '|';
        md += res.users[i].time_zone + '\n';
        ec.ZendeskUsers.push({
            id: res.users[i].id,
            name: res.users[i].name,
            email: res.users[i].email,
            role: res.users[i].role,
            timeZone: res.users[i].time_zone
        });
    }
    return ( {ContentsFormat: formats.json, Type: entryTypes.note, Contents: res, HumanReadable: md, EntryContext: ec} );
};
var fetchIncidents = function() {
    var now = getLastRun();
    var sertime;
    var incidents = [];
    var labels = [];
    if (!params.fetch_interval) {
        params.fetch_interval = 10;
    }
    if (!now.time) {
        sertime = getNowTime((-1) * parseInt(params.fetch_interval));
    } else {
        sertime = now.time;
    }
    var att = {query: 'type:ticket created>' + sertime + ' ' + params.fetchQuery};
    res = sendRequest('GET', 'search.json', '', att);
    if (res.results.length > 0) {
        for (var i = 0; i < res.results.length; i++) {
            var resComments = sendRequest('GET', 'tickets/' + res.results[i].id + '/comments.json');
            resComments.comments[0].attachments.forEach(function(attachment) {
                labels.push({type: 'TicketAttachment', value: attachment.id.toString() + ':' + attachment.file_name});
            });
            var ticketId = res.results[i].id + '';
            labels.push({type: 'TicketId', value: ticketId.toString()});
            labels.push({type: 'TicketSubject', value: res.results[i].subject});
            labels.push({type: 'TicketCreated', value: res.results[i].created_at});
            incidents.push({
                name: parseInt(res.results[i].id) + ' - ' + res.results[i].subject,
                details: res.results[i]['description'],
                labels: labels,
                rawJSON: JSON.stringify(res.results[i]),
                severity: parseInt(res.results[i].priority)
            });
            labels = [];
        }
        setLastRun({'time': res.results[0].created_at});
    }
    return JSON.stringify(incidents);
}
switch (command) {
    // This is the call made when pressing the integration test button.
    case 'test-module':
        var res = sendRequest('GET', 'users/me.json');
        if (res.user.name !== 'Anonymous user' &&
            res.user.id) {
            return 'ok';
        }
        return JSON.stringify(res);
    case 'zendesk-create-ticket':
        return createTicket();
    case 'zendesk-list-tickets':
        return listTickets();
    case 'zendesk-update-ticket':
        return updateTicket();
    case 'zendesk-add-comment':
        return addComment();
    case 'zendesk-ticket-details':
        return getTicketDetails();
    case 'zendesk-list-agents':
        return listAgents();
    case 'zendesk-get-attachment':
        return getAttachment();
    case 'zendesk-get-article':
        return getArticle();
    case 'zendesk-clear-cache':
        setIntegrationContext({});
        return 'Cache cleared';
    case 'zendesk-add-user':
        return addUser();
    case 'fetch-incidents':
        return fetchIncidents();
    default:
        throw 'Zendesk: Unknown command';
}
