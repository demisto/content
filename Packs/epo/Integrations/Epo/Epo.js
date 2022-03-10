//GLOBALS//
var serverUrl = params.address;
if (serverUrl[serverUrl.length - 1] !== '/') {
    serverUrl += '/';
}

var EPO_SYSTEM_ATTRIBUTE_MAP = {
    'EPOComputerProperties.ComputerName': 'Name',
    'EPOComputerProperties.DomainName': 'Domain',
    'EPOComputerProperties.IPHostName': 'Hostname',
    'EPOComputerProperties.IPAddress': 'IPAddress',
    'EPOComputerProperties.OSType': 'OS',
    'EPOComputerProperties.OSVersion': 'OSVersion',
    'EPOComputerProperties.CPUType': 'Processor',
    'EPOComputerProperties.NumOfCPU': 'Processors',
    'EPOComputerProperties.TotalPhysicalMemory': 'Memory',
};

//HELPER//
function callEpo(pCommand, pArgs) {
    var url = serverUrl + 'remote/' + pCommand;
    url += encodeToURLQuery(pArgs);
    url += (Object.keys(pArgs).length > 0) ? '&' : '?';
    url += ':output=json';
    var result = http(
        url,
        {
            Method: 'GET',
            Username: params.authentication.identifier,
            Password: params.authentication.password
        },
        params.insecure,
        params.proxy
    );

    if (isResponseOK(result)) {
        trimmedRes = result.Body.substring(okStr.length);
        trimmedRes = trimmedRes.replace('\n',' ');
        parsedRes = JSON.parse(trimmedRes);
        return parsedRes;
    } else if (result.StatusCode == 200){
        throw 'Error accessing ePO interface. Command: ' + url + ". Body: " +  result.Body;
    } else {
        throw 'Error accessing ePO interface. Command: ' + url + ". Response: " + JSON.stringify(result);
    }
}

function doRawHttp(method, url, parameters, body) {
    if (!parameters) {
        parameters = {};
    }
    var result = http(
        url + encodeToURLQuery(parameters),
        {
            Headers: {'Content-Type': ['application/json']},
            Method: method,
            Body: ''
        },
        params.insecure,
        params.proxy
    );
    if (result.StatusCode < 200 && result.StatusCode > 299) {
        throw 'Failed to perform request ' + url + encodeToURLQuery(parameters) + ', request status code: ' + result.StatusCode;
    }
    return result;
}

function isResponseOK(response) {
    // EPO response if of format: OK -> data. Error: error string
    if (response.StatusCode === 200) {
        okStr = 'OK:';
        if (response.Body.indexOf(okStr) === 0) {
            return true;
        }
    }
    return false;
}

function systemsToMd(systems,verbose) {
    var i;
    var md='';
    if (verbose=="true") {
        for (i=0;i<systems.length;i++) {
            md += systemToMd(systems[i],verbose);
        }
    } else {
        var tmpHead='|';
        var tmpLine='|';
        for (var key in EPO_SYSTEM_ATTRIBUTE_MAP) {
            tmpHead += EPO_SYSTEM_ATTRIBUTE_MAP[key] + '|';
            tmpLine += '-|';
        }
        md += tmpHead + '\n'+tmpLine+'\n';
        for (i=0;i<systems.length;i++) {
            md += systemToMd(systems[i],verbose);
        }
    }
    return md;
}

function systemToMd(system,verbose) {
    var md='';
    var key;
    if (verbose=="true") {
        md += '#### '+ system["EPOComputerProperties.ComputerName"]+'\n';
        md += "Attribute|Value\n-|-\n";
        for (key in system) {
            md += key +"|"+system[key]+"\n";
        }
        md += "---\n";
    } else {
        md +='|';
        for (key in EPO_SYSTEM_ATTRIBUTE_MAP) {
            md += system[key] +"|";
        }
        md += '\n';
    }
    return md;
}

//COMMANDS//
function epoHelp() {
    var pArgs = {};
    if (args.command) {
        pArgs.command = args.command;
    }
    var readyRes = callEpo('core.help',pArgs);
    var md;
    var line;
    var cmd;
    var desc;

    if (args.command) {
        md = '#### ePO Help - ' + args.command + '\n';
        md += readyRes;
    } else {
        parsedRes = Array.isArray(parsedRes) ? parsedRes : [parsedRes];
        md = '#### ePO Help\n';
        for (var i=0;i<parsedRes.length;i++) {
            line = parsedRes[i];
            line = line.replace(/(\r\n|\n|\r)/gm," ");
            if (!args.search || (args.search.toLowerCase() && line.toLowerCase().indexOf(args.search.toLowerCase())>=0))
{
                desc = line.split('-')[1] ? line.split('-')[1].trim() : 'N/A';
                cmd = line.split('-')[0] ? line.split('-')[0].trim() : 'N/A';
                md += '- **' + cmd + "** - " + desc + '\n';
            }
        }
    }
    return {
        Type: entryTypes.note,
        Contents: readyRes,
        ContentsFormat: formats.json,
        HumanReadable: md
    };
}

function epoGetLatestDatRaw() {
    var url = "http://update.nai.com/products/commonupdater/gdeltaavv.ini";
    //Another option is to use avvdat.ini - provided here in case any additional data from that file is needed in the future
    //var url = "http://update.nai.com/Products/CommonUpdater/avvdat.ini"
    result = doRawHttp("GET",url);
    var res = '';
    var sections = result.Body.split('\r\n\r\n');
    var lines = sections[0].split('\r\n');
    for (var i=0;i<lines.length;i++) {
        if (lines[i].indexOf("CurrentVersion")===0){
            return lines[i].split('=')[1];
        }
    }
    throw 'Cannot get McAfee latest DAT file version';
}

function epoGetLatestDat() {
    var datVersion = epoGetLatestDatRaw();
    var md='McAfee Latest DAT file version is: **' + datVersion + '**\n';
    ec = {};
    ec.mcafee = {"latestDAT": datVersion};
    return {
        Type: entryTypes.note,
        Contents: datVersion,
        ContentsFormat: formats.json,
        HumanReadable: md,
        EntryContext: {
                "mcafee(val.latestDAT === obj.latestDAT)": ec.mcafee, //backward compatability
                "McAfee.ePO.latestDAT": datVersion
        }
    };
}

function epoGetCurrentDat() {
    var pArgs = {"searchText":"VSCANDAT1000"};
    var result = callEpo('repository.findPackages', pArgs);
    if (result && result.length>0) {
        result = result[0];
        var epoDAT = result.productDetectionProductVersion.split('.')[0];
        ec = {};
        ec.mcafee = {"epoDAT": epoDAT};
        var md = "McAfee ePO Current DAT file version in repository is: **" + epoDAT + '**\n';
        return {
            Type: entryTypes.note,
            Contents: result,
            ContentsFormat: formats.json,
            HumanReadable: md,
            EntryContext: {
                "mcafee(val.epoDAT==obj.epoDAT)": ec.mcafee, //backward compatability
                "McAfee.ePO.epoDAT": epoDAT
            }
        };
    } else {
        throw 'Error getting current DAT version. Please check that the DAT file exists. Response: ' + JSON.stringify(result);
    }
}

function epoUpdateClientDatTask() {
    var pArgs = {'searchText': 'VSEContentUpdateDemisto'}; //need to configure this task in ePO beforehand
    var result = callEpo('clienttask.find', pArgs);
    if (result && Array.isArray(result)) {
        result = result[0];
    }
    if (result) {
          return result.objectId;
        }
         // If reached here then the response is an empty "OK:", which means VSEContentUpdateDemisto was not found in the server
        throw 'Error getting DAT update task. It seems the task "VSEContentUpdateDemisto" is missing from the EPO server. Please contact support for more details';
}

function epoUpdateClientDat() {
    var clientTask = epoUpdateClientDatTask();
    var pArgs = {'names':args.systems, 'productId':'EPOAGENTMETA', 'taskId':clientTask};

    var options = ['retryAttempts', 'retryIntervalInSeconds', 'abortAfterMinutes', 'stopAfterMinutes', 'randomizationInterval'];
    for (var i=0;i<options.length;i++) {
        if (args[options[i]]) {
            pArgs[options[i]] = args[options[i]];
        }
    }
    var result = callEpo('clienttask.run', pArgs);
    var md = "ePO client DAT update task started: " + result;
    return {
        Type: entryTypes.note,
        Contents: result,
        ContentsFormat: formats.json,
        HumanReadable: md
    };
}

function epoUpdateRepository() {
    var pArgs = {
        'sourceRepository': 'McAfeeHttp',
        'targetBranch':'Current'
    };
    var result = callEpo('repository.pull', pArgs);

    var md = "ePO repository update started.\n";
    md += result;
    return {
        Type: entryTypes.note,
        Contents: result,
        ContentsFormat: formats.json,
        HumanReadable: md
    };
}

function prettifySystemTree(SystemTree) {
    var prettySystemTree = [];
    for (i=0; i < SystemTree.length; i++) {
        var system = SystemTree[i];
        prettySystemTree[i] = {
            'groupId': system.groupId,
            'groupPath': system.groupPath
        };
    }
    return prettySystemTree;
}

function epoGetSystemTreeGroups() {
    var pArgs = {};
    if (args.search) {
        pArgs.searchText=args.search;
    }
    var result = callEpo('system.findGroups', pArgs);
    if (result.length === 0) {
        return 'System Tree Group was not found.';
    }
    var md = "#### ePO System Tree groups\n";
    md += "Group ID | Group path\n-|-\n";
    for (var i=0;i<result.length;i++) {
        md += result[i].groupId + "|" + result[i].groupPath + "\n";
    }
    return {
        Type: entryTypes.note,
        Contents: result,
        ContentsFormat: formats.json,
        HumanReadable: md,
        EntryContext: {
            "McAfee.ePO(val.groupId==obj.groupId)": {'SystemTreeGroups': prettifySystemTree(result)}
        }
    };
}

function epoGetSystemGroupPath(groupId) {
    var result = epoGetSystemTreeGroups();
    result = result.Contents;
    for (var i=0;i<result.length;i++) {
        if (groupId == result[i].groupId) {
            return result[i].groupPath;
        }
    }
    return null;
}

function prettifyFindSystem(FindSystem) {
    var prettyFindSystem = [];
    for (i=0; i < FindSystem.length; i++) {
        var system = FindSystem[i];
        prettyFindSystem[i] = {
            'Name': system['EPOComputerProperties.ComputerName'],
            'Domain': system['EPOComputerProperties.DomainName'],
            'Hostname': system['EPOComputerProperties.IPHostName'],
            'IPAddress': system['EPOComputerProperties.IPAddress'],
            'OS': system['EPOComputerProperties.OSType'],
            'OSVersion': system['EPOComputerProperties.OSVersion'],
            'Processor': system['EPOComputerProperties.CPUType'],
            'Processors': system['EPOComputerProperties.NumOfCPU'],
            'Memory': system['EPOComputerProperties.TotalPhysicalMemory'],
        };
    }
    return prettyFindSystem;
}

function epoFindSystems() {
    var name = epoGetSystemGroupPath(args.groupId);

    if (!name) {
        throw 'System Tree group not found';
    }
    var pArgs = {'groupId':args.groupId};
    var result = callEpo('epogroup.findSystems', pArgs);
    if (result) {
        var md = '#### Systems in '+name+'\n';
        if (result.length>0) {
            md += systemsToMd(result,args.verbose);
        } else {
            md += 'No systems found\n';
        }
        return {
            Type: entryTypes.note,
            Contents: result,
            ContentsFormat: formats.json,
            HumanReadable: md,
            EntryContext: {
                'Endpoint(val.IPAddress==obj.IPAddress)': prettifyFindSystem(result),
                'McAfee.ePO.Endpoint(val.IPAddress==obj.IPAddress)': prettifyFindSystem(result),
            }
        };
    } else {
        throw 'No systems found. Response: ' + JSON.stringify(result);
    }
}

function epoFindSystem() {
    var pArgs = {'searchText':args.searchText};
    var result = callEpo('system.find', pArgs);
    if (result) {
        var md = '#### Systems in the System Tree\n';
        if (result.length>0) {
            md += systemsToMd(result,args.verbose);
        } else {
            md += 'No systems found\n';
        }
        return {
            Type: entryTypes.note,
            Contents: result,
            ContentsFormat: formats.json,
            HumanReadable: md,
            EntryContext: {
                'Endpoint(val.IPAddress==obj.IPAddress)': prettifyFindSystem(result),
                'McAfee.ePO.Endpoint(val.IPAddress==obj.IPAddress)': prettifyFindSystem(result),
            }
        };
    } else {
        throw 'No systems found. Response: ' + JSON.stringify(result);
    }
}

function epoWakeupAgent() {
    var pArgs = {'names':args.names};
    var result = callEpo('system.wakeupAgent', pArgs);

    var md = "ePO agent was awaken.\n";
    md += result;

    return {
        Type: entryTypes.note,
        Contents: result,
        ContentsFormat: formats.json,
        HumanReadable: md
    };
}

function epoApplyTag() {
    var pArgs = {
        'names': args.names,
        'tagName': args.tagName
    };
    var result = callEpo('system.applyTag', pArgs);

    var md = "ePO applied the tags on the hostnames successfully.\n";

    return {
        Type: entryTypes.note,
        Contents: result,
        ContentsFormat: formats.json,
        HumanReadable: md
    };
}

function epoClearTag() {
    var pArgs = {
        'names': args.names,
        'tagName': args.tagName
    };
    var result = callEpo('system.clearTag', pArgs);

    var md = "ePO cleared the tags from the hostnames successfully.\n";

    return {
        Type: entryTypes.note,
        Contents: result,
        ContentsFormat: formats.json,
        HumanReadable: md
    };
}

function epoGetTables() {
    var result;
    var pArgs = {};
    if (args.table) {
        pArgs.table = args.table;
    }

    result = callEpo('core.listTables', pArgs);

    var md = tableToMarkdown(
            'ePO tables:',
            Object.keys(result || {}).map(function (k) { return result[k]; }), // object keys
            args.headers && args.headers.split(',')
        );

    return {
        Type: entryTypes.note,
        Contents: result,
        ContentsFormat: formats.json,
        HumanReadable: md
    };
}

function epoQueryTable() {
    var pArgs = {'target': args.target};
    var result;
    var ec = {};
    var ec_key = '';
    if (args.select) {
        pArgs.select = args.select;
    }
    if (args.where) {
        pArgs.where = args.where;
    }
    if (args.order) {
        pArgs.order = args.order;
    }
    if (args.group) {
        pArgs.group = args.group;
    }
    if (args.joinTables) {
        pArgs.joinTables = args.joinTables;
    }

    result = callEpo('core.executeQuery', pArgs);

    var md = tableToMarkdown(
            'ePO Table Query:',
            Object.keys(result || {}).map(function (k) { return result[k]; }), // object keys
            args.headers && args.headers.split(',')
        );

    if (args.query_name) {
        ec_key = 'McAfee.ePO.Query.' + args.query_name;
    } else {
        var ts = (new Date()).getTime() / 1000;
        ec_key = 'McAfee.ePO.Query.' + ts;
    }
    ec[ec_key] = result;

    return {
        Type: entryTypes.note,
        Contents: result,
        ContentsFormat: formats.json,
        HumanReadable: md,
        EntryContext: ec
    };
}

function epoGetVersion() {
    var pArgs = {};
    var result;

    result = callEpo('epo.getVersion', pArgs);

    var md = "### ePO version is:\n" + result;
    var ec = {"McAfee.ePO.Version": result};

    return {
        Type: entryTypes.note,
        Contents: result,
        ContentsFormat: formats.text,
        HumanReadable: md,
        EntryContext: ec
    };

}

function epoMoveSystem() {
    var pArgs = {
        'names': args.names,
        'parentGroupId': args.parentGroupId
    };

    var result;
    result = callEpo('system.move', pArgs);

    if (result === true) {
        result = 'System ' + args.names + ' moved successfully to GroupId ' +  args.parentGroupId;
        return {
            Type: entryTypes.note,
            Contents: result,
            ContentsFormat: formats.text,
            HumanReadable: result
        };
    } else {
        result = 'System ' + args.names + ' failed to move to GroupId ' + args.parentGroupId;
        return {
            Type: entryTypes.error,
            Contents: result,
            ContentsFormat: formats.text,
            HumanReadable: result
          };
    }
}

function parseCommandArgs(command, commandArgs) {
    //commandArgs should be in the format of:  keyName1:keyValue1, keyName2:KeyValue2
    if (!commandArgs) {
        return null;
    }
    var commandArgsDict = {};
    commandArgsDict.command = command;
    var commandArgsList = commandArgs.split(',');
    var temp = [];
    for (i=0; i < commandArgsList.length; i++) {
        //commandArgsVal in commandArgsList:
        temp = commandArgsList[i].split(':');
        commandArgsDict[temp[0]] = temp[1];
    }
    return commandArgsDict;
}

function epoCommand(parsedArgs) {
    if (parsedArgs) {
        args = parsedArgs;
    }
    var pArgs = {};
    for (var key in args) {
        if (key != 'command' && key != 'headers') {
            pArgs[key] = args[key];
        }
    }
    var result = callEpo(args.command, pArgs);

    var md;
    var contents;
    if (typeof result === 'string') {
        md = "#### ePO command *" + args.command + "* results:\n" + result;
        contents = {result: result};
    } else {

        md = tableToMarkdown(
            'ePO command *' + args.command + '* results:',
            Object.keys(result || {}).map(function (k) { return result[k]; }),// object keys
            args.headers && args.headers.split(',')
        );
        contents = result;
    }
    return {
        Type: entryTypes.note,
        Contents: contents,
        ContentsFormat: formats.json,
        HumanReadable: md
    };
}

switch (command) {
    // This is the call made when pressing the integration test button.
    case 'test-module':
        epoHelp();
        return 'ok';

    case 'epo-help':
        return epoHelp();

    case 'epo-get-latest-dat':
        return epoGetLatestDat();

    case 'epo-get-current-dat':
        return epoGetCurrentDat();

    case 'epo-update-client-dat':
        return epoUpdateClientDat();

    case 'epo-update-repository':
        return epoUpdateRepository();

    case 'epo-get-system-tree-group':
        return epoGetSystemTreeGroups();

    case 'epo-find-systems':
        return epoFindSystems();

    case 'epo-find-system':
        return epoFindSystem();

    case 'epo-wakeup-agent':
        return epoWakeupAgent();

    case 'epo-apply-tag':
        return epoApplyTag();

    case 'epo-clear-tag':
        return epoClearTag();

    case 'epo-get-tables':
        return epoGetTables();

    case 'epo-query-table':
        return epoQueryTable();

    case 'epo-get-version':
        return epoGetVersion();

    case 'epo-move-system':
        return epoMoveSystem();


    case 'epo-command':
        if (!args.command) {
            throw 'ePO error: command argument is missing';
        }
        return epoCommand(undefined);

    case 'epo-advanced-command':
        if (!args.command) {
            throw 'ePO error: command argument is missing';
        }
        if (!args.commandArgs) {
            throw 'ePO error: commandArgs argument is missing';
        }
        var parsedArgs = parseCommandArgs(args.command, args.commandArgs);
        return epoCommand(parsedArgs);

    default:
        throw 'ePO Error: unknown command';
}
