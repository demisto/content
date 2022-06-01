
var username = params.credentials.identifier;
var password = params.credentials.password;
var server = params.server.replace(/[\/]+$/, '');
var insecure = params.insecure;
var proxy = params.proxy;
var url = server + '/webservice/Manager';


var responseDict = {
    'authenticate': /<authenticateReturn>(.*)<\/authenticateReturn/,
    'hostRetrieveAll': /<soapenv:Body>((.|\n)*)<\/soapenv:Body>/,
    'endSession': /<soapenv:Body><endSessionResponse xmlns=(.*)\/><\/soapenv:Body>/,
    'systemEventRetrieve': /<systemEventRetrieveResponse xmlns="urn:Manager">((.|\n)*)<\/systemEventRetrieveResponse>/,
    'antiMalwareEventRetrieve':/<antiMalwareEventRetrieveResponse xmlns="urn:Manager">((.|\n)*)<\/antiMalwareEventRetrieveResponse>/,
    'hostAntiMalwareScan':/<soapenv:Body>((.|\n)*)<\/soapenv:Body>/,
    'alertStatusRetrieve':/<soapenv:Body>((.|\n)*)<\/soapenv:Body>/,
    'securityProfileRetrieveAll': /<soapenv:Body>((.|\n)*)<\/soapenv:Body>/,
    'securityProfileAssignToHost': /<soapenv:Body>((.|\n)*)<\/soapenv:Body>/
};



var commandToMethod = {
    'trendmicro-host-antimalware-scan': 'hostAntiMalwareScan',
    'trendmicro-host-retrieve-all': 'hostRetrieveAll',
    'trendmicro-system-event-retrieve': 'systemEventRetrieve',
    'trendmicro-anti-malware-event-retrieve': 'antiMalwareEventRetrieve',
    'trendmicro-alert-status': 'alertStatusRetrieve',
    'trendmicro-security-profile-retrieve-all': 'securityProfileRetrieveAll',
    'trendmicro-security-profile-assign-to-host': 'securityProfileAssignToHost'
};

var sessionData = '<urn:sID>%sessionId%</urn:sID>';

var methodDict = {
        'authenticate': '<urn:authenticate><urn:username>%username%</urn:username><urn:password>%password%</urn:password></urn:authenticate>',
        'endSession': '<urn:endSession>' + sessionData + '</urn:endSession>',
        'hostRetrieveAll': '<urn:hostRetrieveAll>' + sessionData + '</urn:hostRetrieveAll>',
        'systemEventRetrieve': '<urn:systemEventRetrieve>%timeFilter%%hostFilter%%eventIdFilter%<urn:includeNonHostEvents>%includeNonHostEvents%</urn:includeNonHostEvents>'+ sessionData +'</urn:systemEventRetrieve>',
        'antiMalwareEventRetrieve': '<urn:antiMalwareEventRetrieve>%timeFilter%%hostFilter%%eventIdFilter%'+ sessionData +'</urn:antiMalwareEventRetrieve>',
        'hostAntiMalwareScan': '<urn:hostAntiMalwareScan>%hostIDs%' + sessionData + '</urn:hostAntiMalwareScan>',
        'alertStatusRetrieve': '<urn:alertStatusRetrieve><urn:count>%count%</urn:count>' + sessionData + '</urn:alertStatusRetrieve>',
        'securityProfileRetrieveAll': '<urn:securityProfileRetrieveAll>' + sessionData + '</urn:securityProfileRetrieveAll>',
        'securityProfileAssignToHost':'<urn:securityProfileAssignToHost><urn:securityProfileID>%securityProfileID%</urn:securityProfileID>%hostIDs%' + sessionData + '</urn:securityProfileAssignToHost>'
};

var filterDict = {
    'timeFilter': '<urn:timeFilter>%timeFilter%</urn:timeFilter>',
    'hostFilter': '<urn:hostFilter>%hostFilter%</urn:hostFilter>',
    'eventIdFilter': '<urn:eventIdFilter>%eventIdFilter%</urn:eventIdFilter>'

};



var hostFilterDict = {
    'hostGroupID': '<urn:hostGroupID>%hostGroupID%</urn:hostGroupID>',
    'hostID': '<urn:hostID>%hostID%</urn:hostID>',
    'securityProfileID': '<urn:securityProfileID>%securityProfileID%</urn:securityProfileID>',
    'hostFilterType': '<urn:type>%hostFilterType%</urn:type>'

};

var timeFilterDict = {
  'rangeFrom': '<urn:rangeFrom>%rangeFrom%</urn:rangeFrom>',
  'rangeTo': '<urn:rangeTo>%rangeTo%</urn:rangeTo>',
  'specificTime': '<urn:specificTime>%specificTime%</urn:specificTime>',
  'timeFilterType': '<urn:type>%timeFilterType%</urn:type>'
};

var eventIdFilterDict = {
  'eventID': '<urn:id>%eventID%</urn:id>',
  'eventFilterOperator': '<urn:operator>%eventFilterOperator%</urn:operator>'
};

var filterContentDict = {
    'hostFilter': hostFilterDict,
    'timeFilter': timeFilterDict,
    'eventIdFilter': eventIdFilterDict
};

// Wrap host IDs array if exists
if ('hostIDs' in args) {
        args.hostIDs = '<urn:hostIDs>' + args.hostIDs.split(',').join('</urn:hostIDs><urn:hostIDs>') + '</urn:hostIDs>';
}

function getFilterContent(filterName, args) {
    var filterContent = '';
    filterArgsDict = filterContentDict[filterName];
    var argNames = Object.keys(args);
    for (var i = 0; i < argNames.length; i++) {
        if (argNames[i] in filterArgsDict){
        filterContent += filterArgsDict[argNames[i]];
        }
    }
    if (!filterContent) {
        return '';
    }

    var  filterContents = {};
    filterContents[filterName] = filterContent;
    return replaceInTemplates(filterDict[filterName], filterContents);
}

// In requests with optional filters, the command arguemnts will determine which filters to add
function AddFiltersIfNeeded(reqTemplate, args) {
    var filtersForRequest = {};
    var filterNames = Object.keys(filterDict);
    for (var i = 0; i < filterNames.length; i++) {
        var patt = new RegExp(filterNames[i]);
        if (patt.exec(reqTemplate)) {
            var filterContent = getFilterContent(filterNames[i], args);
            filtersForRequest[filterNames[i]] = filterContent;
        }
    }
    return  replaceInTemplates(reqTemplate, filtersForRequest);
}

function createSOAPRequest(methodName, args) {
    var request = '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:Manager"><soapenv:Header/><soapenv:Body>%content%</soapenv:Body></soapenv:Envelope>';
    var bodyWithFilters = AddFiltersIfNeeded(methodDict[methodName], args);
    request = replaceInTemplates(request, {'content': bodyWithFilters}); // add body to request
    request = replaceInTemplates(request, args); // fill arguemnts
    return request;
}

function sendSOAPRequest(methodName, args) {
    var req = createSOAPRequest(methodName, args);
    var res = http(
        url,
        {
            Method: 'POST',
            Headers: {
            SOAPAction: [""]
            },
            Body: req
        },
        insecure,
        proxy
    );
    if (res.StatusCode < 200 || res.StatusCode >= 300) {
            throw 'Failed to ' + methodName + ', request status code: ' + res.StatusCode + ' and Body: ' + res.Body + '.';
        }
    return res.Body;
}

function sendAndParse(method, args) {
    var responseXML = sendSOAPRequest(method, args);
    var match = responseDict[method].exec(responseXML);
    if (match && match[1]) {
        return match[1];
    }
    throw method +' failed';
}


function createIncidentFromAlert(singleAlert) {
    var keys = Object.keys(singleAlert);
    var labels = [];
    for (var i = 0; i < keys.length; i++) {
        labels.push({'type': keys[i], 'value': String(singleAlert[keys[i]])});
    }
    var alertTime = new Date(singleAlert.alertDate);
    return {
            "name": singleAlert.alertType,
            "occurred": alertTime,
            "labels": labels,
            "rawJSON": JSON.stringify(singleAlert)
        }
}

function fetchIncidents() {
    var lastRun = getLastRun();
    var startTime = lastRun && lastRun.startTime ? lastRun.startTime : 0;
    var maxTime = startTime;
    args.sessionId = sendAndParse('authenticate', {username: username, password: password});
    args.count = 1000;
    var res = JSON.parse(x2j(sendAndParse('alertStatusRetrieve', args)));
    sendAndParse('endSession',args);
    var incidents = [];
    if (res && res.alertStatusRetrieveResponse){
        var alertsDict = res.alertStatusRetrieveResponse.alertStatusRetrieveReturn;
        for (var i in alertsDict) {
            var alertTime = new Date(alertsDict[i].alertDate);
            if (alertTime > startTime) {
                incidents.push(createIncidentFromAlert(alertsDict[i]));
                maxTime = Math.max(alertTime, maxTime);
            }
        }
    }
    setLastRun({startTime: maxTime});
    return JSON.stringify(incidents);
}

switch (command) {
    case 'test-module':
        if (sendAndParse('authenticate', {username: username, password: password})) {
            return 'ok';
        }
        return 'something is wrong';
    case 'fetch-incidents':
        return fetchIncidents();
    default:
        args.sessionId = sendAndParse('authenticate', {username: username, password: password});
        var res = JSON.parse(x2j(sendAndParse(commandToMethod[command], args)));
        sendAndParse('endSession',args);
        return res;
}

