var URI_PREFIX = '/services/data/v39.0/';
var SESSION_DATA = '';

function getNewToken() {
    var request = {
        grant_type: 'password',
        client_id: params.clientID,
        client_secret: params.clientSecret,
        username: params.credentials.identifier,
        password: params.credentials.password
        };

    var body = encodeToURLQuery(request).substr(1);
    var response = http(
        params.InstanceURL + '/services/oauth2/token',
        {
            Method: 'POST',
            Headers: {'Content-Type': ['application/x-www-form-urlencoded']},
            Body: body,
        },
        params.insecure === false,
        params.useproxy
    );
    if (response.StatusCode < 200 || response.StatusCode >= 300) {
        throw 'Failed to get new token, request status code: ' + response.StatusCode + ' and Body: ' + response.Body + '.';
    }
    return JSON.parse(response.Body);
}


function sendRequest(method, url, body, token) {
    var headers = {};
    if (token) {
        headers['Authorization'] = ['Bearer ' + token];
    }
    if (method == 'POST' || method == 'PATCH') {
        headers['Content-Type'] = ['application/json'];
    }
    return http(
        url,
        {
            Method: method,
            Headers: headers,
            Body: body,
        },
        params.insecure === false,
        params.useproxy
    );
}

function sendRequestInSession(method, uri, body) {
    if (!SESSION_DATA || !SESSION_DATA.access_token) {
        throw "Faield to get access token for Salesforce integration.";
    }
    var response = sendRequest(method, SESSION_DATA.instance_url + URI_PREFIX + uri, body, SESSION_DATA.access_token);
    if (response.StatusCode === 401) {
        SESSION_DATA = getNewToken();
        response = sendRequest(method, SESSION_DATA.instance_url + URI_PREFIX + uri, body, SESSION_DATA.access_token);
    }
    if (response.StatusCode < 200 || response.StatusCode >= 300) {
            throw 'Failed to run command uri: ' + uri + ', request status code: ' + response.StatusCode + ' and Body: ' + response.Body + '.';
    }
    return response;
}


function getUserNames() {
    var res = queryObjects(['Id', 'Name'], 'User');
    var users = {};
    for (var i in res.records) {
        users[res.records[i].Id] = res.records[i].Name;
    }

    return users;
}


function commentToEntry(raw_info, title, userMapping) {
    // fix owner field
    if (userMapping) {
        for (var i in raw_info) {
            // use OwnerId if no user was found
            raw_info[i].OwnerId = userMapping[raw_info[i].OwnerId] || raw_info[i].OwnerId;
        }
    }

    return createEntry(raw_info, {
        contextPath: 'SalesForce.CaseComment(val.ID && val.ID == obj.ID)',
        title: title,
        data: [
            {to: 'ID', from: 'Id', humanReadable: false},
            {to: 'ParentId', from: 'ParentId'},
            {to: 'IsPublished', from: 'IsPublished'},
            {to: 'CommentBody', from: 'CommentBody'},
            {to: 'CreatedById', from: 'CreatedById'},
            {to: 'CreatedDate', from: 'CreatedDate'},
            {to: 'SystemModstamp', from: 'SystemModstamp'},
            {to: 'LastModifiedDate', from: 'LastModifiedDate'},
            {to: 'LastModifiedById', from: 'LastModifiedById'},
            {to: 'IsDeleted', from: 'IsDeleted'}
        ]
    });
}


function userToEntry(raw_info, title, userMapping) {
    // fix owner field
    if (userMapping) {
        for (var i in raw_info) {
            // use OwnerId if no user was found
            raw_info[i].OwnerId = userMapping[raw_info[i].OwnerId] || raw_info[i].OwnerId;
        }
    }

    return createEntry(raw_info, {
        contextPath: 'SalesForce.User(val.ID && val.ID == obj.ID)',
        title: title,
        data: [
            {to: 'ID', from: 'Id', humanReadable: false},
            {to: 'Alias', from: 'Alias'},
            {to: 'CommunityNickname', from: 'CommunityNickname'},
            {to: 'CreatedById', from: 'CreatedById'},
            {to: 'Email', from: 'Email'},
            {to: 'LastLoginDate', from: 'LastLoginDate'},
            {to: 'LastModifiedDate', from: 'LastModifiedDate'},
            {to: 'LastName', from: 'LastName'},
            {to: 'Name', from: 'Name'},
            {to: 'Username', from: 'Username'},
            {to: 'UserRoleId', from: 'UserRoleId'}
        ]
    });
}


function orgToEntry(raw_info, title, userMapping) {
    // fix owner field
    if (userMapping) {
        for (var i in raw_info) {
            // use OwnerId if no user was found
            raw_info[i].OwnerId = userMapping[raw_info[i].OwnerId] || raw_info[i].OwnerId;
        }
    }

    return createEntry(raw_info, {
        contextPath: 'SalesForce.GetOrg(val.ID && val.ID == obj.ID)',
        title: title,
        data: [
            {to: 'ID', from: 'Id', humanReadable: false},
            {to: 'Name', from: 'Name'}
        ]
    });
}

function casesToEntry(raw_info, title, userMapping) {
    // fix owner field
    if (userMapping) {
        for (var i in raw_info) {
            // use OwnerId if no user was found
            raw_info[i].OwnerId = userMapping[raw_info[i].OwnerId] || raw_info[i].OwnerId;
        }
    }

    return createEntry(raw_info, {
        contextPath: 'SalesForce.Case(val.ID && val.ID == obj.ID)',
        title: title,
        data: [
            {to: 'ID', from: 'Id', humanReadable: false},
            {to: 'CaseNumber', from: 'CaseNumber'},
            {to: 'Subject', from: 'Subject'},
            {to: 'Description', from: 'Description'},
            {to: 'CreatedDate', from: 'CreatedDate'},
            {to: 'ClosedDate', from: 'ClosedDate'},
            {to: 'Owner', from: 'OwnerId'},
            {to: 'Priority', from: 'Priority'},
            {to: 'Origin', from: 'Origin'},
            {to: 'Status', from: 'Status'},
            {to: 'Reason', from: 'Reason'},
            {to: 'IsEscalated', from: 'IsEscalated'},
            {to: 'SuppliedPhone', from: 'SuppliedPhone'},
            {to: 'SuppliedCompany', from: 'SuppliedCompany'},
            {to: 'SuppliedEmail', from: 'SuppliedEmail'},
            {to: 'ContactEmail', from: 'ContactEmail'},
            {to: 'ContactId', from: 'ContactId'},
            {to: 'AccountId', from: 'AccountId'},
            {to: 'Id', from: 'Id'}

        ]
    });
}


function contactsToEntry(raw_info, title, userMapping, accountMapping) {
    var i;
    // fix owner field
    if (userMapping) {
        for (i in raw_info) {
            // use OwnerId if no user was found
            raw_info[i].OwnerId = userMapping[raw_info[i].OwnerId] || raw_info[i].OwnerId;
        }
    }
    if (accountMapping) {
        for (i in raw_info) {
            // use AccountId if no account was found
            raw_info[i].AccountId = accountMapping[raw_info[i].AccountId] || raw_info[i].AccountId;
        }
    }

    return createEntry(raw_info, {
        contextPath: 'SalesForce.Contact(val.ID && val.ID == obj.ID)',
        title: title,
        data: [
            {to: 'ID', from: 'Id', humanReadable: false},
            {to: 'Name', from: 'Name'},
            {to: 'Account', from: 'AccountId'},
            {to: 'Title', from: 'Title'},
            {to: 'Phone', from: 'Phone'},
            {to: 'Mobile', from: 'MobilePhone'},
            {to: 'Email', from: 'Email'},
            {to: 'Owner', from: 'OwnerId'},
        ]
    });
}

function leadsToEntry(raw_info, title, userMapping) {
    // fix owner field
    if (userMapping) {
        for (var i in raw_info) {
            // use OwnerId if no user was found
            raw_info[i].OwnerId = userMapping[raw_info[i].OwnerId] || raw_info[i].OwnerId;
        }
    }
    return createEntry(raw_info, {
        contextPath: 'SalesForce.Lead(val.ID && val.ID == obj.ID)',
        title: title,
        data: [
            {to: 'ID', from: 'Id', humanReadable: false},
            {to: 'Name', from: 'Name'},
            {to: 'Title', from: 'Title'},
            {to: 'Company', from: 'Company'},
            {to: 'Phone', from: 'Phone'},
            {to: 'Mobile', from: 'MobilePhone'},
            {to: 'Email', from: 'Email'},
            {to: 'Owner', from: 'OwnerId'},
            {to: 'Status', from: 'Status'}
        ]
    });
}

function tasksToEntry(raw_info, title, lead_dict) {
    // fix owner field
    if (leadMapping) {
        for (var i in raw_info) {
            // use WhoId if no lead was found
            raw_info[i].WhoId = leadMapping[raw_info[i].WhoId] || raw_info[i].WhoId;
        }
    }

    return createEntry(raw_info, {
        contextPath: 'SalesForce.Task(val.ID && val.ID == obj.ID)',
        title: title,
        data: [
            {to: 'ID', from: 'Id', humanReadable: false},
            {to: 'Subject', from: 'Subject'},
            {to: 'Lead', from: 'WhoId'},
            {to: 'RelatedTo', from: 'RelatedTo'},
            {to: 'DueDate', from: 'ActivityDate'}
        ]
    });
}

function usersToEntry(raw_info, title) {
    return createEntry(raw_info, {
        contextPath: 'SalesForce.GetUsers(val.ID && val.ID == obj.ID)',
        title: title,
        data: [
            {to: 'ID', from: 'Id', humanReadable: false},
            {to: 'Name', from: 'Name'},
            {to: 'Alias', from: 'Alias'},
            {to: 'CommunityNickname', from: 'CommunityNickname'},
            {to: 'Title', from: 'Title'},
            {to: 'Phone', from: 'Phone'},
            {to: 'Email', from: 'Email'},
            {to: 'FirstName', from: 'FirstName'},
            {to: 'Username', from: 'Username'}
        ]
    });
}

function objectToEntry(obj_type, obj) {
    var userMapping = getUserNames();
    switch (obj_type) {
        case 'CaseComment':
            return commentToEntry([obj], 'CaseComment:', userMapping);
        case 'getOrgName':
            return orgToEntry([obj], 'getOrgName:', userMapping);
        case 'userToEntry':
            return userToEntry([obj],'getUser', userMapping);
        case 'Case':
            return casesToEntry([obj], 'Case:', userMapping);
        case 'Contact':
            accountMapping = undefined; // TODO: implement
            return contactsToEntry([obj], 'Contact:', userMapping, accountMapping);
        case 'Lead':
            return leadsToEntry([obj], 'Lead:', userMapping);
        case 'Task':
            leadMapping = undefined; // TODO: implement
            return tasksToEntry([obj], 'Lead:', leadMapping);
        case 'User':
            return usersToEntry([obj], 'User:');
        default:
            return obj;
    }
}

function queryToEntry(query) {
    return {
        Type : entryTypes.note,
        Contents : query.records,
        ContentsFormat: formats.json,
        ReadableContentsFormat: formats.markdown,
        HumanReadable : tableToMarkdown('Query Results', query.records)
    };
}

function searchToEntry(searchRecords) {
    if (searchRecords.length === 0) {
        return {
            Type : entryTypes.Note,
            Contents : 'No records matched the search.',
            // ContentsFormat: formats.json,
            ReadableContentsFormat: formats.markdown
        };
    }

    var case_ids = [];
    var contact_ids = [];
    var lead_ids = [];
    var task_ids = [];
    var user_ids = [];
    var general = [];
    var case_comment = [];
    var get_org = [];

    for (var i in searchRecords) {
        switch (searchRecords[i].attributes.type) {
            case 'CaseComment':
                case_comment.push(searchRecords[i].Id);
                break;
            case 'getOrgName':
                get_org.push(searchRecords[i].Id);
                break;
            case 'Case':
                case_ids.push(searchRecords[i].Id);
                break;
            case 'Contact':
                contact_ids.push(searchRecords[i].Id);
                break;
            case 'Lead':
                lead_ids.push(searchRecords[i].Id);
                break;
            case 'Task':
                task_ids.push(searchRecords[i].Id);
                break;
            case 'User':
                user_ids.push(searchRecords[i].Id);
                break;
            default:
                // in case we don't know how to parse the object
                general.push(searchRecords[i]);
                break;
        }
    }

    var condition, properties;
    var entries = [];
    var userMapping = getUserNames();
    if (get_org.length > 0) {
        condition = "ID IN ('" + get_org.join("','") + "')";
        properties = ['ID', 'Name'];
        var cases = queryObjects(properties, "Account", condition).records;
        entries.push(orgToEntry(cases, 'Account:', userMapping));
    }

    if (case_ids.length > 0) {
        condition = "ID IN ('" + case_ids.join("','") + "')";
        properties = ['ID', 'CaseNumber', 'Subject', 'Description', 'CreatedDate', 'ClosedDate', 'OwnerID', 'Priority', 'Origin', 'Status', 'Reason','IsEscalated','SuppliedPhone','SuppliedCompany','SuppliedEmail','ContactEmail','ContactId','AccountId'];
        var cases = queryObjects(properties, "Case", condition).records;
        entries.push(casesToEntry(cases, 'Cases:', userMapping));
    }
     if (case_comment.length > 0) {
        condition = "ID IN ('" + case_comment.join("','") + "')";
        properties = ['ID', 'CommentBody', 'CreatedDate', 'CreatedById', 'IsPublished', 'SystemModstamp', 'LastModifiedById', 'LastModifiedDate'];
        var cases_comment = queryObjects(properties, "CaseComment", condition).records;
        entries.push(commentToEntry(cases_comment, 'CaseComment:', userMapping));
    }

    if (contact_ids.length > 0) {
        condition = "ID IN ('" + contact_ids.join("','") + "')";
        properties = ['ID', 'Name', 'Title', 'AccountId', 'Phone', 'MobilePhone', 'Email', 'OwnerId'];
        var contacts = queryObjects(properties, "Contact", condition).records;
        entries.push(contactsToEntry(contacts, 'Contacts:', userMapping));
    }
    if (lead_ids.length > 0) {
        condition = "ID IN ('" + lead_ids.join("','") + "')";
        properties = ['ID', 'Name', 'Title', 'Company', 'Phone', 'MobilePhone', 'Email', 'Status', 'OwnerId'];
        var leads = queryObjects(properties, "Lead", condition).records;
        entries.push(leadsToEntry(leads, 'Leads:', userMapping));
    }
    if (task_ids.length > 0) {
        condition = "ID IN ('" + task_ids.join("','") + "')";
        properties = ['ID', 'Subject', 'WhoId', 'ActivityDate'];
        var tasks = queryObjects(properties, "Task", condition).records;
        entries.push(tasksToEntry(tasks, 'Tasks:'));
    }
    if (user_ids.length > 0) {
        condition = "ID IN ('" + user_ids.join("','") + "')";
        properties = ['ID', 'Name', 'Title', 'Phone', 'Email'];
        var users = queryObjects(properties, "User", condition).records;
        entries.push(usersToEntry(users, 'Users:'));
    }

    if (general.length > 0) entries.push({'unparsed' : general});
    return entries;
}

function queryRaw(query) {
    var url = 'query/' + encodeToURLQuery({q : query});
    response = sendRequestInSession('GET', url, '');
    return JSON.parse(response.Body);
}

function queryObjects(fields, table, condition) {
    query = 'SELECT ' + fields.join(',') + ' FROM ' + table;
    if (condition !== undefined) {
        query += ' WHERE ' + condition;
    }

    return queryRaw(query);
}

function getObject(path) {
    response = sendRequestInSession('GET', 'sobjects/' + path, '');
    return objectToEntry(path.split('/')[0], JSON.parse(response.Body));
}

function createObject(path, json_obj) {
    response = sendRequestInSession('POST','sobjects/' + path, json_obj);
    response = JSON.parse(response.Body);

    if (response.success !== true) {
        return {
            Type: entryTypes.note,
            Contents: response,
            ContentsFormat: formats.json,
            ReadableContentsFormat: formats.markdown,
            HumanReadable : tableToMarkdown('Request failed with errors', response.errors, undefined, undefined, dotToSpace)
        };
    }

    return getObject(path + '/' + response.id);
}

function updateObject(path, json_obj) {
    response = sendRequestInSession('PATCH','sobjects/' + path, json_obj);
    if (response.StatusCode != 204) {
        throw 'object '+ path + ' update failed with status code: ' + response.StatusCode;
    }

    return getObject(path);
}

function deleteObject(path) {
    response = sendRequestInSession('DELETE', 'sobjects/' + path);
    if (response.StatusCode != 204) {
        throw 'object ' + path + ' delete failed with status code: ' + response.StatusCode;
    }

    return 'object ' + path + 'was successfully deleted.';
}

function getCase(oid, caseNumber) {
    if (caseNumber !== undefined) {
        var condition = "CaseNumber='" + caseNumber + "'";
        var properties = ['ID', 'CaseNumber', 'Subject', 'Description', 'CreatedDate', 'ClosedDate', 'OwnerID', 'Priority', 'Origin', 'Status', 'Reason','IsEscalated','SuppliedPhone','SuppliedCompany','SuppliedEmail','ContactEmail','ContactId','AccountId'];
        cases = queryObjects(properties, 'Case', condition).records;
        return casesToEntry(cases, 'Case #' + caseNumber + ':', getUserNames());
    }

    if (oid !== undefined) {
        return getObject('Case/' + oid);
    }

    return {
        Type : entryTypes.error,
        Contents : 'You must specify object ID or a Case Number',
        // ContentsFormat: formats.json,
        ReadableContentsFormat: formats.markdown
    };
}


// Add the capability to get all comment in specific case
function getCaseComment(oid, caseNumber) {
    if (caseNumber !== undefined) {

        var condition = "CaseNumber='" + caseNumber + "'";
        cases = queryObjects(['Id', 'CaseNumber'], 'Case', condition).records;
        comments = JSON.parse(sendRequestInSession('GET', 'sobjects/Case/'+cases[0].Id+'/CaseComments').Body);
        return commentToEntry(comments.records, 'CaseComment #' + cases[0].CaseNumber + ':', getUserNames());
    }

    if (oid !== undefined) {
        comments = JSON.parse(sendRequestInSession('GET', 'sobjects/Case/'+oid+'/CaseComments').Body);
        return commentToEntry(comments.records, 'CaseComment #' + oid + ':', getUserNames());
    }

    return {
        Type : entryTypes.error,
        Contents : 'You must specify object ID or a Case Number',
        // ContentsFormat: formats.json,
        ReadableContentsFormat: formats.markdown
    };
}

function getUser(oid, caseNumber) {
    if (caseNumber !== undefined) {
        var condition = "CaseNumber='" + caseNumber + "'";
        cases = queryObjects(['Id', 'CaseNumber','OwnerId'], 'Case', condition).records;
        var conditionA = "Id='" +  cases[0].OwnerId + "'";
        properties = ['Id', 'Name', 'Alias', 'CommunityNickname', 'Email','FirstName','Username'];
        var users = queryObjects(properties, "User", conditionA).records;
        return usersToEntry(users, 'User #' + cases[0].OwnerId + ':', getUserNames());
    }

    if (oid !== undefined) {
        var usersOid = JSON.parse(sendRequestInSession('GET', 'sobjects/'+'User').Body);
        return usersToEntry(usersToEntry.records, 'User #' + usersOid + ':', getUserNames());
    }

    return {
        Type : entryTypes.error,
        Contents : 'You must specify object ID or a Case Number',
        // ContentsFormat: formats.json,
        ReadableContentsFormat: formats.markdown
    };
}

function getOrgName(caseNumber) {

    if (caseNumber !== undefined) {
        var condition = "CaseNumber='" + caseNumber + "'";
        var properties = ['ID', 'CaseNumber','AccountId'];
        var cases = queryObjects(properties, 'Case', condition).records;
        var conditionA = "Id='" +  cases[0].AccountId + "'";
        var propertiesA = ['Id', 'Name'];
        var usersA = queryObjects(propertiesA, "Account", conditionA).records;
        return orgToEntry(usersA, 'Account #' + cases[0].AccountId + ':', getUserNames());
    }

    return {
        Type : entryTypes.error,
        Contents : 'You must specify a Case Number',
        // ContentsFormat: formats.json,
        ReadableContentsFormat: formats.markdown
    };
}


// Add the capability to post comment in specific case
function postCaseComment(oid,caseNumber,text ) {
    data = {
        CommentBody : text,
        ParentId: caseNumber
    };

    response = sendRequestInSession('POST', 'sobjects/CaseComment', JSON.stringify(data));
    message = JSON.parse(response.Body);
    message.body = text;
    return {
        Type : entryTypes.note,
        Contents : message,
        ContentsFormat: formats.json,
        HumanReadable: tableToMarkdown('comment', message)
    };
}


function createCase(subject, description, status, origin, priority, caseType) {
    var data = {
        Subject : subject,
        Description : description,
        Status : status,
        Origin : origin,
        Priority : priority,
        Type : caseType
    };

    return createObject('Case', JSON.stringify(data));
}

function updateCase(oid, caseNumber, subject, description, status, origin, priority, caseType) {
    if ((oid === undefined) && (caseNumber === undefined)) {
        return {
            Type : entryTypes.error,
            Contents : 'You must specify object ID or a Case Number',
            // ContentsFormat: formats.json,
            ReadableContentsFormat: formats.markdown
        };
    }

    if (oid === undefined) {
        var condition = "CaseNumber='" + caseNumber + "'";
        cases = queryObjects(['ID'], 'Case', condition).records;
        oid = (cases.length === 1) ? cases[0].Id : undefined;
    }

    var data = {
        Subject : subject,
        Description : description,
        Status : status,
        Origion : origin,
        Priority : priority,
        Type : caseType
    };

    return updateObject('Case/' + oid, JSON.stringify(data));
}

function getCases() {
    var properties = ['ID', 'CaseNumber', 'Subject', 'Description', 'CreatedDate', 'ClosedDate', 'OwnerID', 'Priority', 'Origin', 'Status', 'Reason'];
        cases = queryObjects(properties, 'Case').records;
        return casesToEntry(cases, 'Cases:', getUserNames());
}


function closeCase(oid, caseNumber) {
    return updateCase(oid, caseNumber, undefined, undefined, 'Closed');
}

function deleteCase(oid, caseNumber) {
    if ((oid === undefined) && (caseNumber === undefined)) {
        return {
            Type : entryTypes.error,
            Contents : 'You must specify object ID or a Case Number',
            // ContentsFormat: formats.json,
            ReadableContentsFormat: formats.markdown
        };
    }

    if (oid === undefined) {
        var condition = "CaseNumber='" + caseNumber + "'";
        cases = queryObjects(['ID'], 'Case', condition).records;
        oid = (cases.length === 1) ? cases[0].Id : undefined;
    }

    return deleteObject('Case/' + oid);
}

function pushComment(oid, text, linkUrl) {
    data = {
        body : {
            messageSegments : [{
                type : 'Text',
                text : text
            }],
        },
        feedElementType : 'FeedItem',
        subjectId : oid
    };

    if (linkUrl !== undefined) {
        data.body.messageSegments.push({
            type : 'Link',
            url : linkUrl});
    }

    response = sendRequestInSession('POST', 'chatter/feed-elements', JSON.stringify(data));
    message = JSON.parse(response.Body);

    return createEntry(message, {
        title : 'New Message',
        contextPath: 'SalesForce.Comment(val.URL && val.URL == obj.URL)',
        data : [
            {to : 'Body', from : 'body.text'},
            {to : 'CreatedDate', from : 'createdDate'},
            {to : 'Title', from : 'header.text'},
            {to : 'ParentType', from : 'parent.type'},
            {to : 'ParentName', from : 'parent.name'},
            {to : 'URL', from : 'url'},
            {to : 'Visibility', from : 'visibility'}
            ]
    });
}

function pushCommentThread(id, text) {
    var data = {
        body : {
            messageSegments : [{
                type : 'Text',
                text : text
            }]
        }
    };

    var response = sendRequestInSession('POST', 'chatter/feed-elements/'+ id +'/capabilities/comments/items', JSON.stringify(data));
    var message = JSON.parse(response.Body);
    var output = {
        Body: message.body.text,
        CreatedDate: message.createdDate,
        URL: message.url
    };

    ec = {
        'SalesForce.Comment(val.URL && val.URL == obj.URL)': {
            URL: URI_PREFIX + 'chatter/feed-elements/' + id,
            Reply: output
        }
    };

    return {
        Type: entryTypes.note,
        Contents: message,
        ContentsFormat: formats.json,
        ReadableContentsFormat: formats.markdown,
        HumanReadable: tableToMarkdown('New Reply', output),
        EntryContext: ec
    };
}

function casesToIncidents(raw_info, userMapping) {
    var cases = [];
    for (var i in raw_info) {
        cases.push({
            name : raw_info[i].Id + " " + raw_info[i].Subject,
            details : raw_info[i].Description,
            rawJSON : JSON.stringify(raw_info[i]),
            Reason : raw_info[i].Reason
        });
    }
    if (cases.length == 0) {
        return '[]';
    } else {
        return JSON.stringify(cases);
    }
}


function fetchIncident() {
    var fetchType = params.fetchType;

    lastRun = getLastRun();
    if (lastRun.last_case_time === undefined) {
        current_time = new Date();
        current_time.setMonth(current_time.getMonth() - 1); // TODO - remove this line
        lastRun.last_case_time = dateToString(current_time, "%Y-%m-%dT%H:%M:%S.%fZ");
        setLastRun(lastRun);
    }

    var condition;
    var properties;
    var incidents = '[]';

    if (fetchType === 'cases') {
        // query cases from last time
        condition = "CreatedDate>" + lastRun.last_case_time + " ORDER BY CreatedDate DESC";
        properties = ['ID', 'CaseNumber', 'Subject', 'Description', 'CreatedDate', 'ClosedDate', 'OwnerID', 'Priority', 'Origin', 'Status', 'Reason'];

        var cases = queryObjects(properties, "Case", condition).records;

        if (cases.length > 0) {
            new_time = stringToDate(cases[0].CreatedDate, "%Y-%m-%dT%H:%M:%S.%fZ");
            lastRun.last_case_time = dateToString(new_time, "%Y-%m-%dT%H:%M:%S.%fZ");

            setLastRun(lastRun);
            var userMapping = getUserNames();
            incidents = casesToIncidents(cases, userMapping);
        }

    } else { //fetchType === 'comment'

        //query comments from last time

        incidents = '[]';

        //Fetch comment replies
        properties = ['Id', 'CommentBody', 'CreatedDate'];
        condition = "CreatedDate>" + lastRun.last_case_time + " ORDER BY CreatedDate DESC LIMIT 10";
        var replies = queryObjects(properties, "FeedComment", condition).records;

        if (replies.length > 0) {

            var newTime = stringToDate(replies[0].CreatedDate, "%Y-%m-%dT%H:%M:%S.%fZ");
            lastRun.last_case_time = dateToString(newTime, "%Y-%m-%dT%H:%M:%S.%fZ");
            setLastRun(lastRun);

            for (var i = 0; i < replies.length; i++) {

                //Get reply details
                var replyDetails = sendRequestInSession('GET', 'chatter/comments/' + replies[i].Id);
                var data = JSON.parse(replyDetails.Body);
                var feedElement = data.feedElement;
                var parentID = feedElement.id;

                //Get parent details
                var parentDetails = getObject('CaseFeed/' + parentID);
                var parentText = parentDetails.Body;

                if (parentText.indexOf('DemistoID') !== -1) {

                    var messageSegments = data.body.messageSegments;
                    for (var j = 0; j < messageSegments.length; j++)
                    if (messageSegments[j].type === 'Text') {
                        // Found the relavent comment (there's only one), so we return it
                        return JSON.stringify([{
                            name: parentText,
                            details: messageSegments[j].text
                        }]);
                    }
                }
            }
        }
    }

    return incidents;
}

SESSION_DATA = getNewToken();
// The command input arg holds the command sent from the user.
var response;
switch (command) {
    case 'fetch-incidents':
        return fetchIncident();
    case 'salesforce-search':
        response = sendRequestInSession('GET','search/?q=FIND+%7B' + args.pattern +'%7D','');
        return searchToEntry(JSON.parse(response.Body).searchRecords);
    case 'salesforce-query':
        return queryToEntry(queryRaw(args.query));
    case 'salesforce-get-object':
        return getObject(args.path);
    case 'salesforce-update-object':
        return updateObject(args.path, args.json);
    case 'salesforce-create-object':
        return createObject(args.path, args.json);
    case 'salesforce-get-case':
        return getCase(args.oid, args.caseNumber);
     case 'salesforce-get-user':
        return getUser(args.oid, args.caseNumber);
    case 'salesforce-get-casecomment':
        return getCaseComment(args.oid, args.caseNumber);
    case 'salesforce-get-org':
        return getOrgName(args.caseNumber);
    case 'salesforce-post-casecomment':
        return postCaseComment(args.oid, args.caseNumber, args.text);
    case 'salesforce-create-case':
        return createCase(args.subject, args.description, args.status, args.origin, args.priority, args.type);
    case 'salesforce-update-case':
        return updateCase(args.oid, args.caseNumber, args.subject, args.description, args.status, args.origin, args.priority, args.type);
    case 'salesforce-get-cases':
        return getCases();
    case 'salesforce-close-case':
        return closeCase(args.oid, args.caseNumber);
    case 'salesforce-delete-case':
        return deleteCase(args.oid, args.caseNumber);
    case 'salesforce-push-comment':
        return pushComment(args.oid, args.text, args.link);
    case 'salesforce-push-comment-threads':
        return pushCommentThread(args.id, args.text);
    case 'test-module':
        try {
            sendRequestInSession('GET', '', '');
        } catch (err) {
            return 'Connection test failed with error: ' + err + '.';
        }
        return 'ok';
    default:
}
