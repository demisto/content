var SentinelOne = function() {
    var builder = (function() {
        var buildURL = function(urlTemplate, urlArgs) {
            //params.url = params.url.replace(/[\/]+$/, '');
            return replaceInTemplates(urlTemplate, urlArgs);
        };
        var createQueryString = function(queryArgs) {
            return encodeToURLQuery(queryArgs);
        };
        var buildRequestBody = function(bodyArgs) {
            return JSON.stringify(bodyArgs);
        };
        var buildPATH = function(pathTemlate, pathArgs) {
            return replaceInTemplatesAndRemove(pathTemlate, pathArgs);
        };
        return {
            url: buildURL,
            body: buildRequestBody,
            path: buildPATH,
            queryString: createQueryString
        };
    })();

    var group_translator = [
        {to: 'Id' , from: 'id'},
        {to: 'Name', from: 'name'},
        {to: 'PolicyId', from: 'policy_id'},
        {to: 'FilterId', from: 'filter_id'},
        {to: 'UserId', from: 'user_id'},
        {to: 'IsDefault', from: 'is_default'},
        {to: 'CreatedAt', from: 'meta_data.created_at'},
        {to: 'UpdatedAt', from: 'meta_data.created_at'},
        {to: 'Source', from: 'source'},
        {to: 'AdQuery', from: 'ad_query'}
    ];

    var hash_translator = [
        {to: 'Id', from: 'id'},
        {to: 'OsFamily', from: 'os_family'},
        {to: 'IsBlack', from: 'is_black'},
        {to: 'Description', from: 'description'},
        {to: 'UpdatedAt', from: 'updated_at'},
        {to: 'CreatedAt', from: 'created_at'},
        {to: 'UserId', from: 'user_id'},
        {to: 'FromCloud', from:'from_cloud'},
        {to: 'FromImmune', from: 'from_immune'}
    ];

    var exclusion_list_translator = [
        {to: 'Id', from: 'id'},
        {to: 'Name', from: 'name'},
        {to: 'CreatedAt', from: 'meta_data.created_at'},
        {to: 'UpdatedAt', from: 'meta_data.updated_at'},
    ];

    var threat_translator = [
        {to: 'Id' , from: 'id'},
        {to: 'Agent', from: 'agent'},
        {to: 'AgentVersion', from: 'agent_version'},
        {to: 'CreatedDate', from: 'created_date'},
        {to: 'Description', from: 'description'},
        {to: 'SilentThreat', from: 'silent_Threat'},
        {to: 'InQuarantine', from: 'in_quarantine'},
        {to: 'InLearningMode', from: 'in_learning_mode'},
        {to: 'Resolved', from: 'resolved'},
        {to: 'Hidden', from: 'hidden'},
        {to: 'Suspicious', from: 'suspicious'},
        {to: 'LearningMode', from: 'learning_mode'},
        {to: 'MitigationActions', from: 'mitigation_actions'},
        {to: 'MitigationResults', from: 'mitigation_results'},
        {to: 'KillStatus', from: 'mitigation_report.kill.status'},
        {to: 'QuarantineStatus', from: 'mitigation_report.quarantine.status'},
        {to: 'RemediateStatus', from: 'mitigation_report.remediate.status'},
        {to: 'RollbackStatus', from: 'mitigation_report.rollback.status'},
        {to: 'NetworkQuarantineStatus', from: 'mitigation_report.network_quarantine.status'},
        {to: 'AffectedFiles', from: 'affected_files'},
        {to: 'MaliciousGroupId', from: 'malicious_group_id'},
        {to: 'FileId', from: 'file_id.object_id'},
        {to: 'FilePermission', from: 'file_id.permission'},
        {to: 'FilePath', from: 'file_id.path'},
        {to: 'FileContentHash', from: 'file_id.content_hash'},
        {to: 'FileSize', from: 'file_id.size'},
        {to: 'IsSystemFile', from: 'file_id.is_system'},
        {to: 'FileName', from: 'file_id.display_name'},
        {to: 'CreatedAt', from: 'meta_data.created_at'},
        {to: 'UpdatedAt', from: 'meta_data.updated_at'}
    ];

    var activities_translator = [
        {to: 'CreatedAt', from: 'meta_data.created_at'},
        {to: 'OsFamily', from: 'os_family'},
        {to: 'User', from: 'user'},
        {to: 'UserId', from: 'user_id'},
        {to: 'Group', from: 'group'},
        {to: 'Id', from: 'id'},
        {to: 'MitigationPolicyCommand', from: 'mitigation_policy_command'},
        {to: 'AgentId', from: 'agent_id'},
        {to: 'Hash', from: 'hash'},
        {to: 'Description', from: 'description'},
        {to: 'ThreatId', from: 'threat_id'},
        {to: 'ActivityType', from: 'activity_type'}
    ];

    var agent_translator = [
        {to: 'NetworkStatus', from: 'network_status'},
        {to: 'Id', from: 'id'},
        {to: 'GroupId', from: 'group_id'},
        {to: 'AgentVersion', from: 'agent_version'},
        {to: 'IsPendingUninstall', from: 'is_pending_uninstall'},
        {to: 'IsUninstalled', from: 'is_uninstalled'},
        {to: 'IsDecomissioned', from: 'is_decommissioned'},
        {to: 'IsActive', from: 'is_active'},
        {to: 'LastActiveDate', from: 'last_active_date'},
        {to: 'RegisteredAt', from: 'registered_at'},
        {to: 'Uuid', from: 'uuid'},
        {to: 'ExternalIp', from: 'external_ip'},
        {to: 'GroupIp', from: 'group_ip'},
        {to: 'IsUpToDate', from: 'is_up_to_date'},
        {to: 'ThreatCount', from: 'threat_count'},
        {to: 'EncryptedApplications', from: 'encrypted_applications'},
        {to: 'OsName', from: 'software_information.os_name'},
        {to: 'ComputerName', from: 'network_information.computer_name'},
        {to: 'Domain', from: 'network_information.domain'},
        {to: 'Interfaces', from: 'network_information.interfaces'},
        {to: 'Configuration', from: 'configuration'},
        {to: 'CreatedAt', from: 'meta_data.created_at'},
        {to: 'UpdatedAt', from: 'meta_data.updated_at'}
    ];

    var commands = {
        'so-activities': {
            path: "activities",
            method: 'GET',
            extended: true,
            title: 'Sentinel One Activities',
            contextPath: 'SentinelOne.Activities(obj.Id==val.Id)',
            translator: activities_translator
        },
        //Agent
        'so-count-by-filters': {
            path: "agents/count-by-filters",
            method: 'GET'
        },
        'so-agents-count': {
            path: "agents/count",
            method: 'GET'
        },
        'so-agent-decommission': {
            path: "agents/%agent_id%/decommission",
            method: 'POST'
        },
        'so-get-agent': {
            path: "agents/%agent_id%",
            method: 'GET',
            extended: true,
            title: 'Sentinel One Agent',
            contextPath: 'SentinelOne.Agents(obj.Id==val.Id)',
            translator: agent_translator
            },
        'so-agents-query': {
            path: "agents",
            method: 'GET',
            extended: true,
            title: 'Sentinel One Agents',
            contextPath: 'SentinelOne.Agents(obj.Id==val.Id)',
            translator: agent_translator
        },
        'so-get-agent-processes': {
            path: "agents/%agent_id%/processes",
            method: 'GET'
        },
        'so-agent-recommission': {
            path: "agents/%agent_id%/recommission",
            method: 'POST'
        },
        'so-agent-unquarentine': {
            path: "agents/%agent_id%/connect",
            method: 'POST'
        },
        'so-agent-shutdown': {
            path: "agents/%agent_id%/shutdown",
            method:'POST'
        },
        'so-agent-uninstall': {
            path: "agents/%agent_id%/uninstall",
            method: 'POST'
        },
        //Agents action
        'so-agents-broadcast': {
            path: "agents/broadcast",
            method: 'POST'
        },
        'so-agents-connect': {
            path: "agents/connect",
            method: 'POST'
        },
        'so-agents-decommission': {
            path: "agents/decommission",
            method:'POST'
        },
        'so-agents-disconnect': {
            path: "agents/disconnect",
            method: 'POST'
        },
        'so-agents-fetch-logs': {
            path: "agents/fetch-logs",
            method: 'POST'
        },
        'so-agents-shutdown': {
            path: "agents/shutdown",
            method:'POST'
        },
        'so-agents-uninstall': {
            path: "agents/uninstall",
            method: 'POST'
        },
        'so-agents-upgrade-software': {
            path: "agents/update-software",
            method: 'POST'
        },
        //Exclusion list
        'so-create-exclusion-list': {
            path: "exclusion-lists",
            method: "POST",
            extended: true,
            title: 'Sentinel One create exclusion list',
            contextPath: 'SentinelOne.ExclusionLists(val.Id==obj.Id)',
            translator: exclusion_list_translator
        },
        'so-delete-exclusion-list': {
            path: "exclusion-lists/%list_id%",
            method: "DELETE"
        },
        'so-get-exclusion-list': {
            path: "exclusion-lists/%list_id%",
            method: 'GET',
            extended: true,
            title: 'Sentinel One create get list',
            contextPath: 'SentinelOne.ExclusionLists(val.Id==obj.Id)',
            translator: exclusion_list_translator
        },
       'so-get-exclusion-lists': {
            path: "exclusion-lists",
            method: 'GET',
            extended: true,
            title: 'Sentinel One get exclusion lists',
            contextPath: 'SentinelOne.ExclusionLists(val.Id==obj.Id)',
            translator: exclusion_list_translator
        },
        'so-update-exclusion-list': {
            path: "exclusion-lists/%list_id%",
            method: 'PUT'
        },
        //Group
        'so-get-groups': {
            path: "groups?policy_id=%policy_id%",
            method: 'GET',
            title: 'Sentinel One create groups',
            extended: true,
            translator: group_translator,
            contextPath: 'SentinelOne.Groups(val.Id==obj.Id)'
        },
        'so-create-group': {
            path: "groups",
            method: 'POST',
            title: 'Sentinel One create group',
            extended: true,
            translator: group_translator,
            contextPath: 'SentinelOne.Groups(val.Id==obj.Id)'
        },
        'so-get-group': {
            path: "groups/%group_id%",
            method: 'GET',
            title: 'Sentinel One get group',
            extended: true,
            translator: group_translator,
            contextPath: 'SentinelOne.Groups(val.Id==obj.Id)'
        },
        'so-update-group': {
            path: "groups/%group_id%",
            method: 'PUT',
            title: 'Sentinel One update group',
            extended: true,
            translator: group_translator,
            contextPath: 'SentinelOne.Groups(val.Id==obj.Id)'
        },
        'so-delete-group': {
            path: "groups/%group_id%",
            method: 'DELETE'
        },
        'so-add-agent-to-group': {
            path: "groups/%group_id%/add-agents",
            method: 'PUT'
        },
        //System configuration
        'so-set-cloud-intelligence': {
            path: "settings/agents/mode/options",
            method: 'PUT'
        },
        //Hash
        'so-create-hash': {
            path: "hashes",
            method: 'POST',
            extended: true,
            title: 'Sentinel One create hash',
            contextPath: 'SentinelOne.Hashes(val.Id==obj.Id)',
            translator: hash_translator
        },
        'so-delete-hash':{
            path: "hashes/%hash_id%",
            method: 'DELETE'
        },
        'so-get-hash-reputation': {
            path: "hashes/%hash_id%/reputation",
            method: 'GET',
        },
        'so-get-hash': {
            path: "hashes/%hash_id%",
            method: 'GET',
            extended: true,
            title: 'Sentinel One get hash',
            contextPath: 'SentinelOne.Hashes(val.Id==obj.Id)',
            translator: hash_translator
        },
        'so-get-hashes': {
            path: "hashes",
            method: 'GET',
            extended: true,
            title: 'Sentinel One get hashes',
            contextPath: 'SentinelOne.Hashes(val.Id==obj.Id)',
            translator: hash_translator
        },
        'so-update-hash': {
            path: "hashes/%hash%",
            method: 'PUT'
        },
        //Policies
        'so-get-policies': {
            path: "policies",
            method: 'GET'
        },
        'so-create-policy': {
            path: "policies",
            method: 'POST'
        },
        'so-get-policy': {
            path: "policies/%policy_id%",
            method: 'GET'
        },
        'so-update-policy': {
            path: "policies/%policy_id%",
            method: 'PUT'
        },
        'so-delete-policy': {
            path: "policies/%policy_id%",
            method: 'DELETE'
        },
        //Threats
        'so-get-threat': {
            path: "threats/%threat_id%",
            method: 'GET',
            extended: true,
            title: 'Sentinel One Threat',
            contextPath: 'SentinelOne.Threats',
            translator: threat_translator
        },
        'so-get-threats': {
            path: "threats",
            method: 'GET',
            extended: true,
            title: 'Sentinel One Threats',
            contextPath: 'SentinelOne.Threats',
            translator: threat_translator
        },
        'so-threat-summary': {
            path: "threats/summary",
            method: 'GET'
        },
        'so-mark-as-threat': {
            path: 'threats/%threat_id%/mark-as-threat',
            method: 'POST'
        },
        'so-mitigate-threat': {
            path: 'threats/%threat_id%/mitigate/%action%',
            method: 'POST'
        },
        'so-reslove-threats': {
            path: 'threats/%threat_id%/resolve',
            method: 'POST'
        }
    };

    var queryMap = {
        content_hash: true,
        mitigation_status: true,
        activity_type__in: true,
        activity_type__nin: true,
        resolved: true,
        hidden: true,
        display_name: true,
        created_at__lt: true,
        created_at__gt: true,
        created_at__lte: true,
        created_at__gte: true,
        updated_at__lt: true,
        updated_at__gt: true,
        updated_at__lte: true,
        updated_at__gte: true,
        skip: true,
        limit: true,
        participating_fields: true,
        query: true,
        registered_at__lt: true,
        registered_at__gt: true,
        last_active_date__lt: true,
        ast_active_date__gt: true,
        total_memory__lte: true,
        total_memory__gte: true,
        core_count__lte: true,
        core_count__gte: true,
        cpu_count__lte: true,
        cpu_count__gte: true,
        is_active: true,
        infected: true,
        is_pending_uninstall: true,
        is_decommissioned: true,
        is_up_to_date: true,
        encrypted_applications: true,
        id__in: true,
        id__nin: true,
        group_id: true,
        group_id__in: true,
        policy_id__in: true,
        computer_name__like: true,
        agent_version__in: true,
        os_type__in: true,
        machine_type__in: true,
        domain__in: true
    };

    var urlTemplate = "%url%/web/api/v%version%/";
    var loginPath = 'users/login';
    var logoutPath = 'users/logout';
    var statusLBound = 200;
    var statusUBound = 300;
    var apiToken = params.token;
    var userToken;
    var fail = false;
    var success = true;
    var insecure = params.insecure;

    var url = builder.url(urlTemplate, params);

    function getqueryArgs(commadArgs) {
        var queryArgs = {};
        for (var arg in commadArgs) {
            if (queryMap[arg]) {
                queryArgs[arg] = commadArgs[arg];
                delete commadArgs[arg];
            }
        }
        return queryArgs;
    }

    var sendRequest = function(fullurl, method, headers, body) {
        var req = {
            Method: method,
            Headers: headers
        };
        if (body) {
            req.Body = body;
        }
        var res = http(fullurl, req, params.insecure);
        var resBody;
        try {
            resBody = JSON.parse(res.Body);
        } catch (err) {
            resBody = res.Body;
        }
        if (res.StatusCode < statusLBound || res.StatusCode >= statusUBound) {
            throw 'Request Failed.\nStatus code: ' + res.StatusCode +'.\nBody: ' + JSON.stringify(res) + '.';
        }
        return {status: success, body: resBody, statusCode: res.StatusCode};
    };

    var login = function(){
        if(apiToken){
            return {status : 'Success'};
        }
        if(!params.credentials.identifier){
            throw 'Must provide username and password or API Token in order to login';
        }
        var body = builder.body({username: params.credentials.identifier, password: params.credentials.password});
        var headers = {'Content-Type': ['application/json']};
        var res = sendRequest(url + loginPath, 'POST', headers, body);
        if (!res.status) {
            var m = (typeof res.body.message) === 'string' ? res.body.message : JSON.stringify(res.body.message);
            res.message = 'Failed to login.\n' + m;
        } else if (res.body.token) {
            userToken = res.body.token;
            res.message = 'Logged in successfully.';
        } else {
            res.status = fail;
            res.message = 'Failed to login. No token in response';
        }
        return res;
    };

    var logout = function() {
        if(apiToken){
            return {status : 'No need to logout'};
        }
        if (!userToken) {
            return { status: fail, body: null, message: 'Failed to logout from SentinelOne, login token is missing'};
        }
        var headers = {
            'Content-Type': ['application/json'],
            'Authorization': ['Token ' + userToken]
        };
        var res = sendRequest(url + logoutPath, 'POST', headers);
        if (!res.status) {
            throw 'Failed to logout. \n: ' +  JSON.stringify(res);
        }
        return res;
    };

    var logErr = function(logRes, output) {
        var oRes = output.concat('.Response');
        var oMes = output.concat('.ErrorMessage');
        return {
            Type: entryTypes.error,
            Contents: logRes.message,
            ContentsFormat: formats.text,
        };
    };

    var testLog = function() {
        if(!apiToken){
            var loginRes = login();
            if (!loginRes.status) {
                return logErr(loginRes, 'Test.Login');
            }
        }
        var logoutRes = logout();
        if (!logoutRes.status) {
            return logoutRes;
        }
        return 'ok';
    };

    var underscoreToCapital = function(string){
        var ret_string = '_'+string;
        return ret_string.replace(/_([a-z])/g, function (g) { return ' '+g[1].toUpperCase(); });
    };

    var camelToCapital = function(string){
        return string.replace(/[A-Z]/g, function (g) { return ' '+g[0]; });
    };

    var executeCommand = function(commandName){
        if (!apiToken){
            var loginRes = login();
            if (!loginRes.status) {
                return logErr(loginRes, 'ExecuteCommand.Login.Response');
            }
        }

        var cmd = commands[commandName];
        if(commandName !== 'so-agents-upgrade-software'){
            queryMap['os_type'] = true;
        }
        var full = url + builder.path(cmd.path, args) + builder.queryString(getqueryArgs(args));
        var method = cmd.method;
        var headers = {
            'Content-Type': ['application/json'],
            'Authorization': (apiToken? ['APIToken ' + apiToken] : ['Token ' + userToken])
        };
        if(commandName === 'so-update-group' && !args.ad_query){
            args.ad_query = '';
        }
        try {
            var res = sendRequest(full, method, headers, JSON.stringify(args));
        }
        catch(err) {
            logout();
            throw err;
        }
        if(res.statusCode === 204){
            return 'Command executed successfully';
        }
        var entry = {
            Type: entryTypes.note,
            Contents: res.body,
            ContentsFormat: formats.json,
            HumanReadableFormat: formats.markdown
        };
        if (cmd.extended) {
            var translated = mapObjFunction(cmd.translator)(res.body);
            entry.ReadableContentsFormat = formats.markdown;
            entry.HumanReadable = tableToMarkdown(cmd.title, translated, undefined, undefined, camelToCapital);
            if(cmd.contextPath){
                entry.EntryContext = {};
                entry.EntryContext[cmd.contextPath] = createContext(translated);
            }
        }
        else{
            entry.HumanReadable = tableToMarkdown(cmd.title, res.body, undefined, undefined, underscoreToCapital);
        }
        return entry;
    };
    return {
        runTest: testLog,
        execute: executeCommand
    };
};

var sentinelOne = SentinelOne();

switch (command) {
    case 'test-module':
        return sentinelOne.runTest();
    default:
        return sentinelOne.execute(command);
}
