function fixUrl(base) {
    var res = base;
    if (base && base[base.length - 1] !== '/') {
        res = res + '/';
    }
    return res;
}

var PROFILE_ARGS = [
    'firstName',
    'lastName',
    'email',
    'login',
    'secondEmail',
    'middleName',
    'honorificPrefix',
    'honorificSuffix',
    'title',
    'displayName',
    'nickName',
    'profileUrl',
    'primaryPhone',
    'mobilePhone',
    'streetAddress',
    'city',
    'state',
    'zipCode',
    'countryCode',
    'postalAddress',
    'preferredLanguage',
    'locale',
    'timezone',
    'userType',
    'employeeNumber',
    'costCenter',
    'organization',
    'division',
    'department',
    'managerId',
    'manager'
];

var API_POSTFIX = 'api/v1/';
var SERVER_URL = fixUrl(params.url) + API_POSTFIX;
var DEFAULT_SEARCH_LIMIT = 200;
var CLIENT_USERAGENT = 'Demisto/1.0';

function createReadableLog(log){
    var logObject = {};

    var time  = new Date(log.published);
    logObject.Time = time.toLocaleString();
    logObject.Actor = log.actor.displayName + ' (' + log.actor.type + ')';
    logObject.ActorAlternateId = log.actor.alternateId;
    logObject.EventInfo = log.displayMessage;
    logObject.EventOutcome = log.outcome.result + (log.outcome.reason ? ': ' + log.outcome.reason : '');
    logObject.EventSeverity = log.severity;
    logObject.Client = '';
    if(log.client.userAgent){
        var browser = log.client.userAgent.browser;
        var os = log.client.userAgent.os;
        logObject.Client += (browser && browser.toLowerCase() !== 'unknown' ? browser : 'Unknown browser') + ' on ';
        logObject.Client += (os && os.toLowerCase() !== 'unknown' ? os : 'Unknown OS') + ' ';
    }
    if(log.client.device){
        logObject.Client += log.client.device.toLowerCase() !== 'unknown' ? log.client.device : 'Unknown device';
    }
    logObject.RequestIP = log.client.ipAddress;
    logObject.ChainIP = dq(log.request.ipChain, 'ip');

    var targets = '';
    if(log.target){
        log.target.forEach(function(target){
            targets += target.displayName + ' (' + target.type + ')\n';
        });
    }

    logObject.Targets = targets || '-';

    return logObject;
}

function getPagedResults(path, queryParams){
    var results = [];

    do {
        var resObject = sendRequest(path, 'GET', queryParams, '', true);
        results = results.concat(resObject.body);
        var link = resObject.link;

        if(!link || link.length < 2 || queryParams.limit){
            // No next page or limit is specified
            break;
        }
        else{
            // Get the next page for the results
            var afterPattern = /\bafter=(.*)>/;
            var linkMatch = link[1].match(afterPattern);
            if(!linkMatch){
                break;
            }

            queryParams['after'] = linkMatch[1];
        }

    } while(resObject.body.length > 0)

    return results;
}

function buildProfile(args) {
    var profile = {};
    var keys = Object.keys(args);
    for (var i = 0 ; i < PROFILE_ARGS.length; i++) {
        if (args[PROFILE_ARGS[i]]) {
            profile[PROFILE_ARGS[i]] = args[PROFILE_ARGS[i]];
        }
    }
    return profile;
}

function buildCredentials(args) {
    var creds = {};
    if (args.password) {
        var  pswd = { value: args.password };
        creds.password = pswd;
    }
    if (args.passwordQuestion || args.passwordAnswer) {
        var recovery = {
            question: args.passwordQuestion,
            answer: args.passwordAnswer
        };
        creds.recovery_question = recovery;
    }
    if (args.providerName || args.providerType) {
        var provider = {
            name: args.providerName,
            type: args.providerType
        };
        creds.provider = provider;
    }
    return creds;
}

function identLevel(count) {
    var ret='';
    for (var i=0;i<count;i++) {
        ret += '     ';
    }
    return ret;
}

function flattenValue(value, level, isArray) {
    if (!level) {
        level=0;
    }
    if (!value || value === '') {
        return '<br>';
    } else if (typeof value === 'string') {
        return value + '<br>';
    } else {
        var ret = (level>0) ? (identLevel(level-1) + (isArray ? '' : '{') + ' <br>') : '';
        for (var key in value) {
            ret += identLevel(level) + (isArray ? '' : key + ': ') + flattenValue(value[key],level+1,isArray);
        }
        return (level>0) ? (ret + identLevel(level-1) + (isArray ? '' : '}') + '<br>') : ret;
    }

}

function profileToMd(profile) {
    var head = '|';
    var line = '|';
    var data = '|';

    for (var key in profile) {
        head += key + '|';
        line += '-|';
        data += profile[key] + '|';
    }
    return head + '\n' + line + '\n' + data + '\n';
}

function usersToMarkdown(users, verbose) {
    var md='';

    if (!Array.isArray(users)) {
        users = [users] ;
    }

    var user;
    if (verbose==='true') {
        for (var i=0;i<users.length;i++) {
            user=users[i];
            md += '### User: ' + user.profile.login +'\n';
            md += '#### Profile:\n';
            md += profileToMd(user.profile);
            md += '#### Additional data:\n';
            md += 'Key|Value\n-|-\n';
            for (var key in user) {
                if (key !== 'profile') {
                    md += key+'|'+flattenValue(user[key]) + '\n';
                }
            }
        }
    } else {
        md += 'ID|Login|First Name|Last Name|Mobile Phone|Last Login|Status\n-|-|-|-|-|-|-\n';
        for (var j=0; j<users.length; j++) {
            user = users[j];
            md += user.id + '|';
            md += user.profile.login + '|';
            md += user.profile.firstName+'|';
            md += user.profile.lastName+'|';
            md += user.profile.mobilePhone+'|';
            md += user.lastLogin+'|';
            md += user.status+'\n';
        }
    }
    return md;
}

function usersToEntryContext(users) {
    var ec={};
    ec.Account = [];
    if (!Array.isArray(users)) {
        users = [users] ;
    }
    for (var i=0;i<users.length;i++) {
        var user=users[i];
        var ecItem={id:user.id, ID:user.id, Type:'Okta'};
        if (user.profile.firstName || user.profile.lastName) {
            var displayName='';
            displayName += (user.profile.firstName)? user.profile.firstName + ' ' : '';
            displayName += (user.profile.lastName)? user.profile.lastName : '';
            ecItem.DisplayName = displayName.trim();
        }
        if (user.profile.email) {
            ecItem.Email = user.profile.email;
        }
        if (user.profile.login) {
            ecItem.Username = user.profile.login;
        }
        if (user.status) {
            ecItem.Status = user.status;
        }
        if (user.objectClass) {
            ecItem.Groups = user.objectClass;
        }
        if (user.group){
            ecItem.Group = user.group;
        }
        ec.Account.push(ecItem);
    }
    return ec;
}


function sendRequest(path, method, queryParams, body, pagination){
    var url = SERVER_URL.concat(path);
    var query = '';
    if(queryParams){
        query = encodeToURLQuery(queryParams);
    }

    url = url.concat(query);

    // backward compatibility
    if(params.proxy){
        if(params.proxy === 'true'){
            params.proxy = true;
        }
        else if(params.proxy === 'false'){
            params.proxy = false;
        }
    }

    var res = http(
        url,
        {
            Method: method ? method : 'GET',
            Headers: {
                'User-Agent': [CLIENT_USERAGENT],
                Authorization: ['SSWS ' + params.apitoken],
                Accept: ['application/json'],
                'Content-Type': ['application/json']
            },
            Body: body ? JSON.stringify(body) : body
        },
        params.insecure,
        params.proxy
    );
    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        throw 'Failed on request ' + url + ' , request status code: ' + res.StatusCode + ' and Body: ' + res.Body + '.';
    }

    if(pagination){
        return {
            body: JSON.parse(res.Body),
            link: res.Headers.Link
        };
    }

    if(!(res.Body)){
        return '';
    }

    return JSON.parse(res.Body);
}

function getUserId(username){
    var uri = 'users?filter=' + encodeURIComponent('profile.login eq "' + username + '"');
    var res = sendRequest(uri);
    if (res && res.length && res.length === 1) {
        return res[0].id;
    } else {
        throw 'Unable to find userId ' + username + '\n' + JSON.stringify(res);
    }
}

function getGroupId(groupName){
    var group = listGroups(groupName);
    if(!group){
        throw 'Unable to find group ' + groupName + '\n' + JSON.stringify(group);
    }

    return group[0].id;
}

function suspendUserCommand(){
    var userId = getUserId(args.username);

    var res = suspendUser(userId);

    var md = '### Okta user suspended: ' + args.username + '\n';
    md += 'User ID: ' + userId + '\n';
    return {
        Type: entryTypes.note,
        Contents: res,
        ContentsFormat: formats.json,
        HumanReadable: md
    };
}

function suspendUser(userId){
    var uri = 'users/' + userId + '/lifecycle/suspend';

    return sendRequest(uri, 'POST');
}

function unSuspendUser(userId){
    var uri = 'users/' + userId + '/lifecycle/unsuspend';

    return sendRequest(uri, 'POST');
}

function unSuspendUserCommand(){
    var userId = getUserId(args.username);

    var res = unSuspendUser(userId);

    var md = '### Okta user unsuspended: ' + args.username + '\n';
    md += 'User ID: ' + userId + '\n';
    return {
        Type: entryTypes.note,
        Contents: res,
        ContentsFormat: formats.json,
        HumanReadable: md
    };
}


function unlockUserCommand(){
    var userId = getUserId(args.username);

    var res = unlockUser(userId);

    var md = '### Okta user unlocked: ' + args.username + '\n';
    md += 'User ID: ' + userId + '\n';
    return {
        Type: entryTypes.note,
        Contents: res,
        ContentsFormat: formats.json,
        HumanReadable: md
    };
}

function unlockUser(userId){
    var uri = 'users/' + userId + '/lifecycle/unlock';
    return sendRequest(uri, 'POST');
}

function deactivateUserCommand() {
    var userId = getUserId(args.username);

    var res = deactivateUser(userId);

    var md = '### Okta user deactivated: ' + args.username + '\n';
    md += 'User ID: ' + userId + '\n';
    return {
        Type: entryTypes.note,
        Contents: res,
        ContentsFormat: formats.json,
        HumanReadable: md
    };
}

function deactivateUser(userId){
    var uri = 'users/' + userId + '/lifecycle/deactivate';

    return sendRequest(uri, 'POST');
}

function activateUserCommand(){
    var userId = getUserId(args.username);

    var res = activateUser(userId);

    var md = '### Okta user activated: ' + args.username + '\n';
    md += 'User ID: ' + userId + '\n';
    return {
        Type: entryTypes.note,
        Contents: res,
        ContentsFormat: formats.json,
        HumanReadable: md
    };
}

function activateUser(userId) {
    var uri = 'users/' + userId + '/lifecycle/activate';

    return sendRequest(uri, 'POST');
}

function getGroupsCommand() {
    var userId = getUserId(args.username);

    var results = getGroups(userId);
    var hr = getGroupsHumanReadable(results);
    var ec = {
        Group: hr,
        ID: userId,
        Type: 'Okta'
    };

    var md = '### Okta groups for user ' + args.username + '\n';
    md += 'User ID: ' + userId + '\n';
    md += tableToMarkdown('Groups', hr);
    return {
        Type: entryTypes.note,
        EntryContext: {
            'Account(val.ID===obj.ID)' : ec
        },
        Contents: results,
        ContentsFormat: formats.json,
        HumanReadable: md
    };
}

function getGroupsHumanReadable(results){
    if(!Array.isArray(results)){
        results = [results];
    }

    var groups = [];
    results.forEach(function(resGroup){
        var group = {
            ID: resGroup.id,
            Created: resGroup.created,
            ObjectClass: resGroup.objectClass,
            LastUpdated: resGroup.lastUpdated,
            LastMembershipUpdated: resGroup.lastMembershipUpdated,
            Type: resGroup.type,
            Name: resGroup.profile.name,
            Description: resGroup.profile.description
        };

        groups.push(group);
    });

    return groups;
}

function getGroups(userId) {
    var uri = 'users/' + userId + '/groups';

    return sendRequest(uri);
}

function listGroupsCommand(){
    var results = listGroups(args.query, args.filter, args.limit);

    var hr = getGroupsHumanReadable(results);

    return {
        Type: entryTypes.note,
        entryContext: {
            'Okta.Group(val.ID===obj.ID)' : hr
        },
        Contents: results,
        ContentsFormat: formats.json,
        HumanReadable: tableToMarkdown('Groups', hr)
    };
}

function listGroups(query, filter, limit){
    var queryParams = {};

    if(filter){
        queryParams.filter = filter;
    }

    if(query){
        queryParams.q = encodeURIComponent(query);
    }

    if(limit){
        queryParams.limit = limit;
    }

    return getPagedResults('groups', queryParams);
}

function getGroupMembersCommand(){
    var groupId = args.groupId;
    var groupName = args.groupName;

    if(!groupId && !groupName){
        throw 'Missing arguments for command';
    }

    if(!groupId){
        groupId = getGroupId(groupName);
    }

    var members = getGroupMembers(groupId, args.limit);
    var group = getGroupsHumanReadable(listGroups(groupName)[0]);

    members.forEach(function(member){
        member.group = group;
    });

    var md = usersToMarkdown(members, args.verbose);
    var ec = usersToEntryContext(members);

    var entry = {
        Type: entryTypes.note,
        EntryContext: ec,
        Contents: members,
        ContentsFormat: formats.json,
        HumanReadable: md
    };

    return entry;
}

function getGroupMembers(groupId, limit){
    queryParams = {};

    if(limit){
        queryParams.limit = limit;
    }

    return getPagedResults('groups/' + groupId + '/users', queryParams);
}

function addUserToGroupCommand(){
    var groupId = args.groupId;
    var userId = args.userId;
    var username = args.username;
    var groupName = args.groupName;

    if((!userId && !username) || (!groupId && !groupName)){
        throw 'Missing arguments for command';
    }

    if(!userId){
        userId = getUserId(username);
    }

    if(!groupId){
        groupId = getGroupId(groupName);
    }

    var res = addUserToGroup(userId, groupId);

    return 'Succesfully added user to group';
}

function addUserToGroup(userId, groupId){
    var uri = 'groups/' + groupId + '/users/' + userId;

    return sendRequest(uri, 'PUT');
}

function removeUserFromGroupCommand(){
    var groupId = args.groupId;
    var userId = args.userId;
    var username = args.username;
    var groupName = args.groupName;

    if((!userId && !username) || (!groupId && !groupName)){
        throw 'Missing arguments for command';
    }

    if(!userId){
        userId = getUserId(username);
    }

    if(!groupId){
        groupId = getGroupId(groupName);
    }

    var res = removeUserFromGroup(userId, groupId);

    return 'Succesfully removed user from group';
}

function removeUserFromGroup(userId, groupId){
    var uri = 'groups/' + groupId + '/users/' + userId;

    return sendRequest(uri, 'DELETE');
}

function setPasswordCommand(){
    var userId = getUserId(args.username);

    var res = setPassword(userId, args.password);

    var md = '### Okta user password set: ' + args.username + '\n';
    md += 'User ID: ' + userId + '\n';
    return {
        Type: entryTypes.note,
        Contents: res,
        ContentsFormat:
        formats.json,
        HumanReadable: md
    };
}

function setPassword(userId, password) {
    var uri = 'users/' + userId;

    var body =  {
        'credentials': {
            'password' : { 'value': password }
        }
    };

    return sendRequest(uri, 'POST', null, body);
}

function searchCommand(){
    var limit = args.limit ? args.limit : DEFAULT_SEARCH_LIMIT;
    var term = args.term ? encodeURIComponent(args.term) : args.term;

    var res = search(term, limit);

    var md;
    var ec;
    if (res && res.length>0) {
        md = '### Okta users found:\n';
        md += usersToMarkdown(res, args.verbose);
        ec = usersToEntryContext(res);
    }
    else {
        md = '### No users found in Okta\n';
    }

    return {
        Type: entryTypes.note,
        EntryContext: ec,
        Contents: res,
        ContentsFormat: formats.json,
        HumanReadable: md
    };
}

function search(term, limit) {
    var uri = 'users?q=' + term + '&limit=' + limit;

    return sendRequest(uri);
}

function getUserCommand(){
    var term = args.username ? encodeURIComponent(args.username) : args.userid;

    if (!term) {
        throw "You must supply either 'username' or 'userid'";
    }

    var res = getUser(term);

    var md = '### Okta user:\n';
    md += usersToMarkdown(res,args.verbose);
    var ec = usersToEntryContext(res);
    return {
        Type: entryTypes.note,
        EntryContext: ec,
        Contents: res,
        ContentsFormat: formats.json,
        HumanReadable: md
    };
}

function getUser(term){
    var uri = 'users/' + term;

    return sendRequest(uri);
}

function getUserFactorsCommand(){
    var userId = args.userId;
    var username = args.username;

    if(!userId && !username){
        throw "You must supply either 'username' or 'userid'";
    }

    if(!userId){
        userId = getUserId(username);
    }

    var factors = getUserFactors(userId);

    if(!factors || factors.length === 0){
        return 'No factors found';
    }

    var mappedFactors = [];
    var hr = [];

    factors.forEach(function(factor){
       mappedFactors.push({
           ID: factor.id,
           FactorType: factor.factorType,
           Provider: factor.provider,
           Status: factor.status,
           Profile: factor.profile
       });

       hr.push({
           'ID': factor.id,
           'Factor Type': factor.factorType,
           'Provider': factor.provider,
           'Status': factor.status
       });
    });

    var md = tableToMarkdown('Okta available factors for user with ID: ' + userId, hr);
    var account = {
        ID: userId,
        Factor: mappedFactors
    };

    return {
        Type: entryTypes.note,
        Contents: factors,
        ContentsFormat: formats.json,
        HumanReadable: md,
        EntryContext: {
            'Account(val.ID===obj.ID)': account
        }
    };
}

function getUserFactors(userId){
    var uri = 'users/' + userId + '/factors';

    return sendRequest(uri);
}

function verifyPushCommand(){
    var userId = args.userId;
    var factorId = args.factorId;
    var response = verifyPush(userId, factorId);

    if (!response) {
        throw 'Did not receive a response from the factor challenge';
    }

    var links = response._links;

    if (!links || !links.poll){
        throw 'Did not recieve a polling link for the push factor challenge';
    }

    var result = pollVerifyPush(links.poll.href);

    var account = {
        ID: userId,
        VerifyPushResult: result.factorResult
    };

    return {
        Type: entryTypes.note,
        EntryContext: {
            'Account(val.ID===obj.ID)': account
        },
        Contents: response,
        ContentsFormat: formats.json,
        HumanReadable: 'Verify push factor result: ' + account.VerifyPushResult
    };
}

function verifyPush(userId, factorId){
    var path = '/users/' + userId + '/factors/' + factorId + '/verify';

    return sendRequest(path, 'POST');
}


function pollVerifyPush(verifyLink){
    // Get the query string of the link
    var index = verifyLink.indexOf(API_POSTFIX);
    var path = verifyLink.substr(index + API_POSTFIX.length);

    do {
        var response = sendRequest(path);
        if (!response) {
            throw 'Did not receive a response from the factor verfication';
        }

        // Wait 5 seconds
        wait(5);

    } while (response.factorResult === 'WAITING')

    return response;
}

function resetFactorCommand(){
    var userId = args.userId;
    var username = args.username;
    var factorId = args.factorId;

    if(!userId && !username){
        throw "You must supply either 'username' or 'userid'";
    }

    if(!userId){
        userId = getUserId(username);
    }

    var response = resetFactor(userId, factorId);

    return {
        Type: entryTypes.note,
        Contents: response,
        ContentsFormat: formats.json,
        HumanReadable: 'Successfully reset factor for user with ID: ' + userId
    };
}

function resetFactor(userId, factorId){
    var path = '/users/' + userId + '/factors/' + factorId;

    return sendRequest(path, 'DELETE');
}

function createUserCommand(){
    var cred = buildCredentials(args);
    var profile = buildProfile(args);
    var groupIds = args.groupIds;
    if (groupIds) {
        groupIds = groupIds.split(',');
    }

    var activate = false;
    if (args.activate) {
        activate = args.activate.toLowerCase() === 'true';
    }

    var res = createUser(cred, profile, groupIds, activate);

    var md = '### Okta user created: ' + args.login + '\n';
    md += profileToMd(res.profile);
    var ec = usersToEntryContext(res);
    return {
        Type: entryTypes.note,
        EntryContext: ec,
        Contents: res,
        ContentsFormat: formats.json,
        HumanReadable: md
    };
}

function createUser(cred, profile, groupIds, activate) {
    var body = {
        profile: profile,
        groupIds: groupIds,
        credentials: cred
    };

    var uri = 'users?activate=' + activate;
    if (cred && cred.provider) {
        uri += '&provider=true';
    }

    return sendRequest(uri, 'POST','', body);
}

function updateUserCommand() {
    var userId = getUserId(args.username);
    var cred = buildCredentials(args);
    var profile = buildProfile(args);
    profile.login = args.username;

    var res = updateUser(userId, profile, cred);
    var md = '### Okta user updated: ' + args.username + '\n';
    md += 'User ID: ' + userId + '\n';
    md += profileToMd(res.profile);
    return {
        Type: entryTypes.note,
        Contents: res,
        ContentsFormat: formats.json,
        HumanReadable: md
    };
}

function updateUser(userId, profile, cred){
    var body = {
        profile: profile,
        credentials: cred
    };

    var uri = 'users/' + userId;

    return sendRequest(uri, 'POST', '', body);
}

function getLogs(filter, query, since, until, sortOrder, limit)
{
    var queryParams = {};

    if(filter){
        queryParams.filter =  filter;
    }

    if(query){
        queryParams.q = encodeURIComponent(query);
    }

    if(since){
        queryParams.since = since;
    }

    if(until){
        queryParams.until = until;
    }

    if(sortOrder){
        queryParams.sortOrder = sortOrder;
    }

    if(limit){
        queryParams.limit = limit;
    }

    return getPagedResults('logs', queryParams);
}

function getFailedLoginsCommand(){
    var readableLogs = [];
    var filter = 'eventType eq "user.session.start" and outcome.result eq "FAILURE"';
    var logs = getLogs(filter, args.query, args.since, args.until, args.sortOrder, args.limit);

    if(!logs || logs.length === 0){
        return 'No events found';
    }

    for(var i = 0; i < logs.length; i++){
        readableLogs.push(createReadableLog(logs[i]));
    }

    var md = tableToMarkdown('Failed Login events', readableLogs);

    return {
        Type: entryTypes.note,
        Contents: logs,
        ContentsFormat: formats.json,
        EntryContext: {
            'Okta.Logs.Events(val.uuid===obj.uuid)' : logs
        },
        HumanReadable: md
    };
}

function getGroupAssignmentsCommand(){
    var readableLogs = [];
    var filter = 'eventType eq "group.user_membership.add"';
    var logs = getLogs(filter, args.query, args.since, args.until, args.sortOrder, args.limit);

    if(!logs || logs.length === 0){
        return 'No events found';
    }

    for(var i = 0; i < logs.length; i++){
        readableLogs.push(createReadableLog(logs[i]));
    }

    var md = tableToMarkdown('Group assignment events', readableLogs);

    return {
        Type: entryTypes.note,
        Contents: logs,
        ContentsFormat: formats.json,
        EntryContext: {
            'Okta.Logs.Events(val.uuid===obj.uuid)' : logs
        },
        HumanReadable: md
    };
}

function getApplicationAssignmentsCommand(){
    var readableLogs = [];
    var filter = 'eventType eq "application.user_membership.add"';
    var logs = getLogs(filter, args.query, args.since, args.until, args.sortOrder, args.limit);

    if(!logs || logs.length === 0){
        return 'No events found';
    }

    for(var i = 0; i < logs.length; i++){
        readableLogs.push(createReadableLog(logs[i]));
    }

    var md = tableToMarkdown('Application assignment events', readableLogs);

    return {
        Type: entryTypes.note,
        Contents: logs,
        ContentsFormat: formats.json,
        EntryContext: {
            'Okta.Logs.Events(val.uuid===obj.uuid)' : logs
        },
        HumanReadable: md
    };
}

function getApplicationAuthenticationCommand(){
    var readableLogs = [];
    var filter = 'eventType eq "user.authentication.sso"';
    var logs = getLogs(filter, args.query, args.since, args.until, args.sortOrder, args.limit);

    if(!logs || logs.length === 0){
        return 'No events found';
    }

    for(var i = 0; i < logs.length; i++){
        readableLogs.push(createReadableLog(logs[i]));
    }

    var md = tableToMarkdown('Application authentication events', readableLogs);

    return {
        Type: entryTypes.note,
        Contents: logs,
        ContentsFormat: formats.json,
        EntryContext: {
            'Okta.Logs.Events(val.uuid===obj.uuid)' : logs
        },
        HumanReadable: md
    };
}

function getLogsCommand(){
    var readableLogs = [];
    var logs = getLogs(args.filter, args.query, args.since, args.until, args.sortOrder, args.limit);

    if(!logs || logs.length === 0){
        return 'No events found';
    }

    for(var i = 0; i < logs.length; i++){
        readableLogs.push(createReadableLog(logs[i]));
    }

    var md = tableToMarkdown('Okta events', readableLogs);

    return {
        Type: entryTypes.note,
        Contents: logs,
        ContentsFormat: formats.json,
        EntryContext: {
            'Okta.Logs.Events(val.uuid===obj.uuid)' : logs
        },
        HumanReadable: md
    };
}

function test() {
    var uri = 'users/me';
    var res = sendRequest(uri);

    return res ? 'ok' : 'not ok';
}

var entry;
switch (command){
    case 'test-module':
        return test();
    case 'okta-unlock-user':
        entry = unlockUserCommand();
        break;
    case 'okta-deactivate-user':
        entry = deactivateUserCommand();
        break;
    case 'okta-activate-user':
        entry = activateUserCommand();
        break;
    case 'okta-get-groups':
        entry = getGroupsCommand();
        break;
    case 'okta-set-password':
        entry = setPasswordCommand();
        break;
    case 'okta-search':
        entry = searchCommand();
        break;
    case 'okta-get-user':
        entry = getUserCommand();
        break;
    case 'okta-create-user':
        entry = createUserCommand();
        break;
    case 'okta-update-user':
        entry = updateUserCommand();
        break;
    case 'okta-get-failed-logins':
        entry = getFailedLoginsCommand();
        break;
    case 'okta-get-group-assignments':
        entry = getGroupAssignmentsCommand();
        break;
    case 'okta-get-application-assignments':
        entry = getApplicationAssignmentsCommand();
        break;
    case 'okta-get-application-authentication':
        entry = getApplicationAuthenticationCommand();
        break;
    case 'okta-add-to-group':
        entry = addUserToGroupCommand();
        break;
    case 'okta-remove-from-group':
        entry = removeUserFromGroupCommand();
        break;
    case 'okta-get-logs':
        entry = getLogsCommand();
        break;
    case 'okta-list-groups':
        entry = listGroupsCommand();
        break;
    case 'okta-get-group-members':
        entry = getGroupMembersCommand();
        break;
    case 'okta-suspend-user':
        entry = suspendUserCommand();
        break;
    case 'okta-unsuspend-user':
        entry = unSuspendUserCommand();
        break;
    case 'okta-get-user-factors':
        entry = getUserFactorsCommand();
        break;
    case 'okta-verify-push-factor':
        entry = verifyPushCommand();
        break;
    case 'okta-reset-factor':
        entry = resetFactorCommand();
        break;
}


return entry;
