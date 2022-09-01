var mdAlertFields={
  'Execution Time':'executionTime',
  'Rule':'rules.rule.name',
  'User':'execUser',
  'Database':'database.name',
  'Sensor':'identifyingSensor.name',
  'Command Type':'cmdType'
};

var fixUrl = function(base) {
    res = base;
    if (base && base[base.length - 1] != '/') {
        res = res + '/';
    }
    return res;
};

var sendRequest = function(url, service, param) {

    // handle '/' at the end of the url
    if (url[url.length - 1] === '/') {
        url = url.substring(0, url.length - 1);
    }

    // prepare the request url (make sure to encode the query parameter value)
    var requestUrl = url + 'service=' + service;
    if  (param) {
        requestUrl += '&' +  param;
    }
    var res = http(
        requestUrl,
        {
            Method: 'GET', // Can be POST, PUT, DELETE, HEAD, OPTIONS or CONNECT
            Headers: {
                Accept: ['application/json']
            },
            Username:  params.credentials.identifier,
            Password:  params.credentials.password,

        },
        !params.insecure
    );

    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        throw 'Request Failed.\nStatus code: ' + res.StatusCode + '.\nBody: ' + JSON.stringify(res) + '.';
    }

    return JSON.parse(x2j(res.Body));
};

var finalUrl = fixUrl(params.url) + 'xmlapi.svc?';

var calculateNewLastRun = function(alerts) {
    var res = '';
    var lastAlert = null;
    if (alerts && alerts.length && alerts.length > 0) {
        // transalte yyyy-MM-dd HH:mm:ss.S +Z => yyyy-MM-ddTHH:mm:ss.S+Z => time in millis
        lastAlert = alerts[alerts.length -1];
    } else if (alerts){
        //This is a single element
        lastAlert = alerts;
    }
    if (lastAlert) {
        var createDate = lastAlert.createDate;
        var dateTime = createDate.split(' ');
        var goTime = dateTime[0]+'T'+dateTime[1]+dateTime[2];
        //hack needed, becuase platform problems
        res = new Date(Date.parse(goTime)).getTime() + 1;
    }
    return res;
};

var alertToIncident = function(alert) {
    labels = [];
    var keys = Object.keys(alert);
    for (j = 0 ; j < keys.length; j++) {
        if (keys[j] === 'accessedObjects') {
            if (alert.accessedObjects.object && alert.accessedObjects.object.length > 0) {
                for (k = 0; k < alert.accessedObjects.object.length; k++) {
                    labels.push({type: 'accessedObject', value: alert.accessedObjects.object[k].owner + '.' + alert.accessedObjects.object[k].name + '('+ alert.accessedObjects.object[k].type +')'});
                }
            }
        } else if (keys[j] === 'database') {
            labels.push({type: 'database-host', value: alert.database.host});
            labels.push({type: 'database-ip', value: alert.database.ip});
            labels.push({type: 'database-id', value: alert.database.id});
            labels.push({type: 'database-name', value: alert.database.name});
        } else if (keys[j] === 'identifyingSensor') {
            labels.push({type: 'sensor-host', value: alert.identifyingSensor.host});
            labels.push({type: 'sensor-ip', value: alert.identifyingSensor.ip});
            labels.push({type: 'sensor-id', value: alert.identifyingSensor.id});
            labels.push({type: 'sensor-name', value: alert.identifyingSensor.name});
            labels.push({type: 'sensor-version', value: alert.identifyingSensor.version});
        } else if (keys[j] === 'rules') {
            if (alert.rules.length > 0) {
                for (k = 0; k < alert.rules.length; k++) {
                    labels.push({type: 'rule', value: alert.rules[i].name + '('+ alert.rules[i].sysid +')'});
                }
            } else if (alert.rules) {
                labels.push({type: 'rule', value: alert.rules.name + '('+ alert.rules.sysid +')'});
            }
        } else {
            labels.push({type: keys[j], value: alert[keys[j]]});
        }
    }
    return {
      name: 'DAM Event - ' + alert.id,
      labels: labels,
      details: alert.operation,
      rawJSON: JSON.stringify(alert)
    };
};
var alertsToIncident = function(alerts) {
    var incidents = [];
    for (i = 0; i < alerts.length; i++){
        incidents.push(alertToIncident(alerts[i]));
    }
    return incidents;
};
function alertsToMd(alerts) {
    var md="";
    if (Array.isArray(alerts)) {
        for (var i in alerts) {
            md += alertToMd(alerts[i]) + "\n --- \n";
        }
    } else {
        md += alertToMd(alerts);
    }
    return md;
}
function mdTableHead() {
    var head='|';
    var line='|';
    for (var key in mdAlertFields) {
        head+=key + '|';
        line+= '- |';
    }
    return head+'\n'+line+'\n';
}
function mdTableData(alert) {
    var data='|';
    for (var key in mdAlertFields) {
        data+=resolve(alert,mdAlertFields[key]) + '|';
    }
    return data + '\n';
}
function alertToMd(alert) {
    var md ='';
    md +="### DAM Alert ID " + alert.id + "\n";
    md += mdTableHead();
    md += mdTableData(alert);
    if (alert.operation) {
        md += '#### Statement\n';
        md += '```\n' + alert.operation + '\n```';
    }
    if (alert.accessedObjects && alert.accessedObjects.object) {
        var objects = Array.isArray(alert.accessedObjects.object) ? alert.accessedObjects.object : new Array(alert.accessedObjects.object);
        md += '\n#### Accessed Objects \n';
        md += 'Type|Owner|Name\n-|-|-\n';
        for (var i in objects) {
            md += objects[i].type + '|' + objects[i].owner + '|' + objects[i].name + "\n";
        }
    }

    return md;
}

function resolve(obj,path) {
    if (Array.isArray(obj)) {
        var ret = [];
        for (var i in obj) {
            ret.push(resolve(obj[i],path));
        }
        return ret;
    } else {
        var dot=path.indexOf(".");
        if (dot == -1) {
            return obj[path] ? obj[path] : 'N/A';
        } else {
            var curr = path.substring(0,dot);
            var rest = path.substring(dot+1);
            return obj[curr] ? resolve(obj[curr],rest) : 'N/A';
        }
    }
}

var fetchIncidents = function() {
    var count = params.batchSize || 100;
    //Default time back for first fetch is 10 minutes
    var timeBack = 1000 * 60 * 10;
    var urlParams = 'HH$TimeBackPeriod=' + encodeURIComponent(timeBack +'');
    var lastRun = getLastRun();
    if (lastRun && Object.keys(lastRun).length > 0) {
        urlParams = 'HH$CreateDateFrom=' + encodeURIComponent(lastRun.createDate);
    }
    if (params.ruleName) {
        urlParams +='&HH$RuleName=' + encodeURIComponent(params.ruleName);
    }
    urlParams += '&HH$pageSize='+encodeURIComponent(count);
    var res = sendRequest(finalUrl, 'alert',  urlParams).HedgehogXmlApi;
    var incidents = null;
    var newLastRun = null;
    if (res && res.alert && res.alert.length > 0) {
        //Create incidents
        incidents = alertsToIncident(res.alert);
        //Set last run
        newLastRun = calculateNewLastRun(res.alert);
    } else if (res && res.alert) {
        //This is a sinlge alert
        //Create incidents
        incidents = [alertToIncident(res.alert)];
        //Set last run
        newLastRun = calculateNewLastRun(res.alert);
    }
    if (newLastRun) {
        setLastRun({createDate: newLastRun});
    }
    return incidents;
};

// The command input arg holds the command sent from the user.
switch (command) {
    // This is the call made when pressing the integration test button.
    case 'test-module':
        sendRequest(finalUrl, 'sensor');
        return 'ok';
    case 'fetch-incidents':
        return JSON.stringify(fetchIncidents());
    case 'dam-get-alert-by-id':
        var jsonRes=sendRequest(finalUrl, 'alert', 'HH$Id=' + encodeURIComponent(args.id)).HedgehogXmlApi.alert;
        if (jsonRes) {
            var entryContext = {
            };
            md = alertToMd(jsonRes);
            return {Type: entryTypes.note, Contents: jsonRes, ContentsFormat: formats.json, HumanReadable: md};
        } else {
            md = '### no alerts found\n';
            return {Type: entryTypes.note, Contents: null, ContentsFormat: formats.json, HumanReadable: md};
        }
    case 'dam-get-latest-by-rule':
        var count = args.count || 10;
        var timeBack = 1000 * 60 * (args.timeBack || 10);
        var res = sendRequest(finalUrl, 'alert', 'HH$RuleName=' + encodeURIComponent(args.ruleName) +
            '&HH$TimeBackPeriod='+encodeURIComponent(timeBack +'') + '&HH$pageSize='+encodeURIComponent(count)).HedgehogXmlApi;

        if (res && res.alert) {
            jsonRes = res.alert;
            var entryContext = {};
            md = alertsToMd(jsonRes);
            return {Type: entryTypes.note, Contents: jsonRes, ContentsFormat: formats.json, HumanReadable: md};
        } else {
            md = '### no alerts found\n';
            return {Type: entryTypes.note, Contents: null, ContentsFormat: formats.json, HumanReadable: md};
        }
}
