var username = params.credentials.identifier;
var password = params.credentials.password;
var server = params.server + ':' + params.port;
var insecure = params.insecure;
var proxy = params.proxy;

var getCSRFToken = function(url) {
    var res = http(
            url,
            {
                Method: 'GET',
                Username: username,
                Password: password
            },
            insecure,
            proxy
        );
    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        throw 'Failed to get CSRF token, request status code: ' + res.StatusCode + ' and Body: ' + res.Body + '.';
    }

    for (var ix in res.Cookies) {
        if (res.Cookies[ix].Name.toLowerCase() === 'csrftoken') {
            return res.Cookies[ix].Value;
        }
    }
    return 'Failed to get CSRF token, Please verify credentials and check GRR logs.';
}

var sendRequest = function(method, url, queryName, body) {
    var csrfToken = getCSRFToken(url);
    var res = http(
            url,
            {
                Method: method,
                Username: username,
                Password: password,
                Body: body,
                Headers: {'X-CSRFToken': [csrfToken]},
                Cookies: [{Name: 'csrftoken', Value: csrfToken, Path: '/', MaxAge: 300}]
            },
            insecure,
            proxy
        );
    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        throw 'Failed to ' + (queryName || 'get main page') + ', request status code: ' + res.StatusCode + ' and Body: ' + res.Body + '.';
    }
    return res.Body;
}

var parseJSON = function(raw){
    var output = null;
    var innerParse = function(i){
        var att = null;
        if(typeof i === 'object' && 'value' in i){
            if (typeof i.value === 'object'){
                i = JSON.parse(JSON.stringify(i.value));
            }else {
                i = i.value;
            }
        }

        if(typeof i === 'object'){
            att = {};
            for (var k in i){
                if (k == "urn"){
                    if(typeof i[k] === 'object' && 'value' in i[k]){
                        if (typeof i[k].value === 'object'){
                            i[k] = JSON.parse(JSON.stringify(i[k].value));
                        }else {
                            i[k] = i[k].value;
                        }
                    }
                    if(typeof i[k] === 'string'){
                        var urn = i[k].split('/');
                        if (urn.length > 0){
                            att.id = urn[urn.length - 1];
                        }
                    }
                }
                if (typeof i[k] === 'object'){
                    att[k] = parseJSON(i[k]);
                } else {
                    att[k] = i[k];
                }
            }
        }
        else{
            att = i;
        }
        return att;
    }

    if(raw instanceof Array){
        output = [];
        raw.forEach(function(row){
            output.push(innerParse(row))
        })
    } else {
        output = innerParse(raw);
    }

    return output;
}
var getHunts = function(method, url, queryName, body, jsonPath, title) {
    var raw = JSON.parse(sendRequest(method, url, queryName, body).slice(5));
    var output = parseJSON(jsonPath ? dq(raw,jsonPath) : raw);

    if(!(output instanceof Array )){
        output = [output];
    }

    var context = { Hunt : [] };
    output.forEach(function(i){
        var huntEntity = {
            ID : i.id,
            Created : i.created,
            Creator : i.creator,
            Description : i.description,
            Expires : i.expires,
            IsRobot : i.is_robot,
            Name: i.name,
            State: i.state
        };

        context.Hunt.push(huntEntity);
    });

    return {
          Type: entryTypes.note,
          Contents: raw,
          ContentsFormat: formats.json,
          HumanReadable: tblToMd(title,output,argToList(args.headers)),
          EntryContext: context
      };
};

var getHunt = function(method, url, queryName, body, jsonPath, title) {
    var raw = JSON.parse(sendRequest(method, url, queryName, body).slice(5));
    var output = parseJSON(jsonPath ? dq(raw,jsonPath) : raw);

    if(!(output instanceof Array )){
        output = [output];
    }

    var context = { Hunt : [] };
    output.forEach(function(i){
        var huntEntity = {
            ID : i.id,
            Created : i.created,
            Creator : i.creator,
            Description : i.description,
            Expires : i.expires,
            IsRobot : i.is_robot,
            Name: i.name,
            State: i.state
        };

        context.Hunt.push(huntEntity);
    });

    return {
          Type: entryTypes.note,
          Contents: raw,
          ContentsFormat: formats.json,
          HumanReadable: tblToMd(title,output,argToList(args.headers)),
          EntryContext: context
      };
};

var getFlows = function(method, url, queryName, body, jsonPath, title) {
    var raw = JSON.parse(sendRequest(method, url, queryName, body).slice(5));
    var output = parseJSON(jsonPath ? dq(raw,jsonPath) : raw);
    if(!(output instanceof Array )){
        output = [output];
    }

    var context = { Flow : [] };

    output.forEach(function(i){
        var flowEntity = {
            ID : i.id,
            Created : i.created,
            Creator : i.creator,
            Description : i.description,
            Expires : i.expires,
            IsRobot : i.is_robot,
            Name: i.name,
            State: i.state,
            Args : i.args,
            LastActiveAt : i.last_active_at,
            NestedFlow : (i.nested_flows && typeof i === 'object' ? i.nested_flows.map(function(a) {return a.id}) : i.nested_flows), //i.nested_flows.map(function(a) {return a.id}),
            StartedAt : i.started_at
        };

        context.Flow.push(flowEntity);
    });

    return {
          Type: entryTypes.note,
          Contents: raw,
          ContentsFormat: formats.json,
          HumanReadable: tblToMd(title,output,argToList(args.headers)),
          EntryContext: context
      };
};

var getClients = function(method, url, queryName, body, jsonPath, title) {
    var raw = JSON.parse(sendRequest(method, url, queryName, body).slice(5));
    var output = parseJSON(jsonPath ? dq(raw,jsonPath) : raw);
    if(!(output instanceof Array )){
        output = [output];
    }

    var context = { Client : [] };

    output.forEach(function(i){
        var clientEntity = {
            FirstSeenAt : i.first_seen_at,
            ID : i.id,
            LastBootedAt : i.last_booted_at,
            LastClock : i.last_clock,
            LastCrashAt : i.last_crash_at,
            LastSeenAt : i.last_seen_at,
            AgentInfo : i.agent_info,
            HardwareInfo : i.hardware_info,
            Interfaces : i.interfaces,
            Labels : i.labels,
            OS : i.os_info,
            User : i.users,
            Volumes : i.volumes
        };

        context.Client.push(clientEntity);
    });

    return {
          Type: entryTypes.note,
          Contents: raw,
          ContentsFormat: formats.json,
          HumanReadable: tblToMd(title,output,argToList(args.headers)),
          EntryContext: context
      };
};

var sendRequestAndParse = function(method, url, queryName, body) {
    return JSON.parse(sendRequest(method, url, queryName, body).slice(5));
};

switch (command) {
    case 'test-module':
        return sendRequest('GET', server) ? 'ok' : 'No body in response';
    case 'grr-set-flows':
    case 'grr_set_flows'://deprecated
        return getFlows('POST', server + '/api/clients/' + args.client_id + '/flows', 'post flow', '{"flow": ' + args.flow + '}',null,"Set Flow");
    case 'grr-get-files': 
    case 'grr_get_files'://deprecated
        var pathsArr;
        try {
            pathsArr = JSON.parse(args.paths);
        } catch (e) {
            logDebug('input is not a valid JSON trying to split');
            pathsArr = args.paths ? args.paths.split(",") : [];
        }
        args.paths = pathsArr;
        return sendRequestAndParse('POST', server + '/api/robot-actions/get-files', 'post get-files', JSON.stringify(args));
    case 'grr-get-hunts':
    case 'grr_get_hunts'://deprecated
        return getHunts('GET', server + '/api/hunts' + encodeToURLQuery(args), 'get hunts',null,"items",'Hunts');
    case 'grr-get-hunt':
    case 'grr_get_hunt'://deprecated
        return getHunt('GET', server + '/api/hunts/' + args.hunt_id, 'get hunt',null,"","Hunt {0}".format(args.hunt_id));
    case 'grr-set-hunts':
    case 'grr_set_hunts'://deprecated
        return getHunts('POST', server + '/api/hunts', 'set hunts', JSON.stringify(args),null,null,"Set Hunt");
    case 'grr-get-clients':
        return getClients('GET',server + '/api/clients' + encodeToURLQuery(args), 'get client',null,"items","Clients");
    case 'grr-get-flows':
    case 'grr_get_flows'://deprecated
        var urlArgs = {};
        if (args.count) {
            urlArgs.count = args.count;
        }
        if (args.offset) {
            urlArgs.offset = args.offset;
        }
        return getFlows('GET', server + '/api/clients/' + args.client_id + '/flows' + encodeToURLQuery(urlArgs), 'get flow',null,"items","Flows");
}
