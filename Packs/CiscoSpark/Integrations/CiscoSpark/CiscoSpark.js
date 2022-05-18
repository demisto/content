var apiKey = params.apiKey;
var insecure = params.insecure;
var proxy = params.proxy;
var server = params.server;

if (server[server.length - 1] === '/') {
    server = server.substring(0, server.length - 1);
}

server = params.server + '/v1';

commandParams = {
    'cisco-spark-list-people':                  {'url': 'people', 'method': 'GET'},
    'cisco-spark-create-person':                {'url': 'people', 'method': 'POST'},
    'cisco-spark-get-person-details':           {'url': 'people/%personId%', 'method': 'GET'},
    'cisco-spark-update-person':                {'url': 'people/%personId%', 'method': 'PUT'},
    'cisco-spark-delete-person':                {'url': 'people/%personId%', 'method': 'DELETE'},
    'cisco-spark-get-own-details':              {'url': 'people/me', 'method': 'GET'},

    'cisco-spark-list-rooms':                   {'url': 'rooms', 'method': 'GET'},
    'cisco-spark-create-room':                  {'url': 'rooms', 'method': 'POST'},
    'cisco-spark-get-room-details':             {'url': 'rooms/%roomId%', 'method': 'GET'},
    'cisco-spark-update-room':                  {'url': 'rooms/%roomId%', 'method': 'PUT'},
    'cisco-spark-delete-room':                  {'url': 'rooms/%roomId%', 'method': 'DELETE'},

    'cisco-spark-list-memberships':             {'url': 'memberships', 'method': 'GET'},
    'cisco-spark-create-membership':            {'url': 'memberships', 'method': 'POST'},
    'cisco-spark-get-membership-details':       {'url': 'memberships/%membershipId%', 'method': 'GET'},
    'cisco-spark-update-membership':            {'url': 'memberships/%membershipId%', 'method': 'PUT'},
    'cisco-spark-delete-membership':            {'url': 'memberships/%membershipId%', 'method': 'DELETE'},

    'cisco-spark-list-messages':                {'url': 'messages', 'method': 'GET'},
    'cisco-spark-create-message':               {'url': 'messages', 'method': 'POST'},
    'cisco-spark-get-message-details':          {'url': 'messages/%messageId%', 'method': 'GET'},
    'cisco-spark-delete-message':               {'url': 'messages/%messageId%', 'method': 'DELETE'},

    'cisco-spark-list-teams':                   {'url': 'teams', 'method': 'GET'},
    'cisco-spark-create-team':                  {'url': 'teams', 'method': 'POST'},
    'cisco-spark-get-team-details':             {'url': 'teams/%teamId%', 'method': 'GET'},
    'cisco-spark-update-team':                  {'url': 'teams/%teamId%', 'method': 'PUT'},
    'cisco-spark-delete-team':                  {'url': 'teams/%teamId%', 'method': 'DELETE'},

    'cisco-spark-list-team-memberships':        {'url': 'team/memberships', 'method': 'GET'},
    'cisco-spark-create-team-membership':       {'url': 'team/memberships', 'method': 'POST'},
    'cisco-spark-get-team-membership-details':  {'url': 'team/memberships/%membershipId%', 'method': 'GET'},
    'cisco-spark-update-team-membership':       {'url': 'team/memberships/%membershipId%', 'method': 'PUT'},
    'cisco-spark-delete-team-membership':       {'url': 'team/memberships/%membershipId%', 'method': 'DELETE'},

    'cisco-spark-list-webhooks':                {'url': 'webhooks', 'method': 'GET'},
    'cisco-spark-create-webhook':               {'url': 'webhooks', 'method': 'POST'},
    'cisco-spark-get-webhook-details':          {'url': 'webhooks/%webhookId%', 'method': 'GET'},
    'cisco-spark-update-webhook':               {'url': 'webhooks/%webhookId%', 'method': 'PUT'},
    'cisco-spark-delete-webhook':               {'url': 'webhooks/%webhookId%', 'method': 'DELETE'},

    'cisco-spark-list-organizations':           {'url': 'organizations', 'method': 'GET'},
    'cisco-spark-get-organization-details':     {'url': 'organizations/%organizationId%', 'method': 'GET'},

    'cisco-spark-list-licenses':                {'url': 'licenses', 'method': 'GET'},
    'cisco-spark-get-license-details':          {'url': 'licenses/%licenseId%', 'method': 'GET'},

    'cisco-spark-list-roles':                   {'url': 'roles', 'method': 'GET'},
    'cisco-spark-get-role-details':             {'url': 'roles/%roleId%', 'method': 'GET'},
}

var buildEmptyEntryContext = function() {
    return {Type: entryTypes.note, Contents: null, ContentsFormat: formats.json, EntryContext: {}};
}

var cloneDict = function(x) {
    var y = {};
    Object.keys(x).forEach(function(key) {
        y[key] = x[key];
    })

    return y;
}

var capitalize = function(string) {
    return string.charAt(0).toUpperCase() + string.slice(1);
}

var capitalizeKeys = function(dict) {
    var capitalizedDict = {};
    for (var key in dict) {
        var capitalizedKey = capitalize(key);
        capitalizedDict[capitalizedKey] = dict[key];
    }

    return capitalizedDict;
}

var updateContext = function(entry, outputs, contextPath) {
    var contexts = [];
    for (var i = 0; i < outputs.length; i++) {
        contexts.push(capitalizeKeys(outputs[i]));
    }
    entry.EntryContext[contextPath] = contexts;
}

var sendRequest = function(method, url) {
    var body = null;
    var requestUrl = server + '/' + url;

    if (method == 'GET') {
        // query parameters
        requestUrl += encodeToURLQuery(args);
    } else {
        // request parameters (body)
        body = JSON.stringify(args);
    }

    var res = http(
        requestUrl,
        {
            Method: method,
            Body: body,
            Headers: {
                'Content-Type': ['application/json'],
                'Authorization': ['Bearer ' + apiKey],
                'Accept': ['application/json']
            },
        },
        insecure,
        proxy
    );

    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        throw 'Request Failed.\nStatus code: ' + res.StatusCode + '.\nResponse: ' + JSON.stringify(res);
    }

    if (res.Body.length > 0) {
        return JSON.parse(res.Body);
    } else {
        return null;
    }
}

var processCommand = function(command) {
    return sendRequest(
        commandParams[command].method,
        replaceInTemplatesAndRemove(commandParams[command].url, args)
    );
}

var parseResponse = function(command, res) {
    var entry;
    if (res) {
        var isListCommand = (command.indexOf('list') != -1);
        var outputs = isListCommand ? res.items : res;

        if (outputs.length === 0) {
            return 'Response is empty.';
        }

        entry = buildEmptyEntryContext();
        entry.HumanReadable = tableToMarkdown('Cisco Spark Results', outputs);
        entry.Contents = res;
        entry.ContentsFormat = formats.json;

        if (isListCommand) {
            var splitCommand = command.split('-');
            var listType = capitalize(splitCommand[splitCommand.length - 1]);
            updateContext(entry, outputs, 'CiscoSpark.' + listType);
        }

    } else {
        // for commands which return nothing
        entry = 'Command succesful.';
    }

    return entry;
}

var sendMessageToPerson = function() {
    if ((!args.toPersonEmail) && (!args.toPersonId)) {
        throw 'Either email or personId must be provided.';
    }

    return processCommand('cisco-spark-create-message');
}

var sendMessageToRoom = function() {
    if (args.toRoomName) {
        var res = processCommand('cisco-spark-list-rooms');
        var rooms = res.items;
        var roomId;
        for (var i = 0; i < rooms.length; i++) {
            if (rooms[i].title.indexOf(args.toRoomName) != -1) {
                if (roomId) {
                    throw 'More than one room starts with the given name: ' + args.toRoomName;
                }

                roomId = rooms[i].id;
            }
        }

        if (!roomId) {
            throw 'A room with the given name was not found: ' + args.toRoomName;
        }

        args.roomId = roomId;
        delete args.toRoomName;

    } else if (!args.roomId) {
        throw 'Either room name or roomId must be provided.';
    }

    return processCommand('cisco-spark-create-message');
}

var res;
switch (command) {
    case 'test-module':
        command = 'cisco-spark-list-people';
        args = {'email': 'test@email.com'};

        // test successful authorization
        processCommand(command);
        return 'ok';

    case 'cisco-spark-send-message-to-person':
        res = sendMessageToPerson();
        break;

    case 'cisco-spark-send-message-to-room':
        res = sendMessageToRoom();
        break;

    default:
        res = processCommand(command);
        break;
}

return parseResponse(command, res);
