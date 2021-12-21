var username = params.credentials.identifier;
var password = params.credentials.password;
var server = params.server.replace(/[\/]+$/, '');
var insecure = params.insecure;
var proxy = params.proxy;
var baseAFF = server + '/WebServices/WSDispatcher.pl';
var baseAFA = server + '/afa/php/ws.php';
var baseBF = server + '/BusinessFlow/rest/v1/network_objects/find';

function fillInSoapContent(content, service) {
    var request = service === 'AFF' ? '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsh="https://www.algosec.com/WSHandler"><soapenv:Header/><soapenv:Body>%content%</soapenv:Body></soapenv:Envelope>' : '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:afa="https://www.algosec.com/afa-ws"><soapenv:Header/><soapenv:Body>%content%</soapenv:Body></soapenv:Envelope>';
    return replaceInTemplates(request, {content: content});
}

function fillInSOAPRequestTemplate(method, content, service) {
    var template = service === 'AFF' ? '<wsh:%method%><FFWSHeader><version>1</version></FFWSHeader>%content%</wsh:%method%>' : '<afa:%method%>%content%</afa:%method%>';
    return fillInSoapContent(replaceInTemplates(template, {content: content, method: method}), service);
}

var responseDict = {
    'authenticate': /<sessionId xsi:type="xsd:string">(.*)<\/sessionId/,
    'getTicket': /<soap:Body>((.|\n)*)<\/soap:Body/,
    'createTicket': /<soap:Body>((.|\n)*)<\/soap:Body/,
    'ConnectRequest': /<SessionID>(.*)<\/SessionID/,
    'DisconnectRequest': /<ns1:DisconnectResponse>(.*)<\/ns1:DisconnectResponse/,
    'QueryRequest': /<SOAP-ENV:Body>((.|\n)*)<\/SOAP-ENV:Body/
};

var commandToMethod = {
    'algosec-get-ticket': 'getTicket',
    'algosec-create-ticket': 'createTicket',
    'algosec-query': 'QueryRequest'
};

var commandToURL = {
    'algosec-get-applications': '/applications',
    'algosec-get-network-object': ''
};

var sessionData = '<sessionId>%sessionId%</sessionId>';
var methodDict = {
    'authenticate': '<username>%username%</username><password>%password%</password>',
    'getTicket': sessionData + '<ticketId>%ticketId%</ticketId>',
    'trafficLines': '<trafficLines><action>%action%</action><trafficDestination><address>%destAddress%</address></trafficDestination><trafficService><service>ftp</service></trafficService><trafficSource><address>%sourceAddress%</address></trafficSource><trafficUser><user>%user%</user></trafficUser><trafficApplication><application>%application%</application></trafficApplication></trafficLines>',
    'createTicket': sessionData + '<ticket><requestor>%requestor%</requestor><subject>%subject%</subject>%trafficLines%</ticket>',
    'ConnectRequest': '<UserName>%username%</UserName><Password>%password%</Password>',
    'DisconnectRequest': '<SessionID>%sessionId%</SessionID>',
    'QueryRequest': '<SessionID>%sessionId%</SessionID><QueryInput>%query%</QueryInput>',
    'QueryInput': '<Source>%source%</Source><Destination>%destination%</Destination><Service>%service%</Service>'
};

var affCommands = ['algosec-create-ticket', 'algosec-get-ticket'];
var bfCommands = ['algosec-get-applications', 'algosec-get-network-object'];

function createTemplate(method, args) {
    switch (method) {
        case 'createTicket':
            var trafficLines =
            (args.description ? '<description>"%description%"</description>' : '') +
            methodDict['trafficLines'];
            return replaceInTemplates(methodDict[method], {trafficLines: trafficLines});
        case 'QueryRequest':
            var query = methodDict['QueryInput'] +
            (args.user ? '<User>%user%</User>' : '') +
            (args.application ? '<Application>%application%</Application>' : '');
            return replaceInTemplates(methodDict[method], {query: query});
        default:
            return methodDict[method];
    }
}

function sendSOAPRequest(method, args, service) {
    var req = fillInSOAPRequestTemplate(method, replaceInTemplates(createTemplate(method, args), args), service);
    var res = http(
        service === 'AFF' ? baseAFF : baseAFA,
        {
            Method: 'POST',
            Body: req
        },
        insecure,
        proxy
    );
    if (res.StatusCode < 200 || res.StatusCode >= 300) {
            throw 'Failed to ' + method + ', request status code: ' + res.StatusCode + ' and Body: ' + res.Body + '.';
        }
    return res.Body;
}

function sendRESTRequest(url, args) {
    var res = http(
        baseBF + url + encodeToURLQuery(args),
        {
            Method: 'GET',
            Username: username,
            Password: password
        },
        insecure,
        proxy
    );
    if (res.StatusCode < 200 || res.StatusCode >= 300) {
            throw 'Failed to ' + url + ', request status code: ' + res.StatusCode + ' and Body: ' + res.Body + '.';
        }
    return res.Body;
}

function sendAndParse(method, args, service) {
    var responseXML = sendSOAPRequest(method, args, service);
    var match = responseDict[method].exec(responseXML);
    if (match && match[1]) {
        return match[1];
    }
    throw method +' failed';
}

if (command === 'test-module') {
    if (sendAndParse('authenticate', {username: username, password: password}, 'AFF')) {
        return 'ok';
    }
    return 'something is wrong';
}

if (affCommands.indexOf(command) !== -1) {
    args.sessionId = sendAndParse('authenticate', {username: username, password: password}, 'AFF');
    return JSON.parse(x2j(sendAndParse(commandToMethod[command], args, 'AFF')));
}

if (bfCommands.indexOf(command) !== -1) {
    return JSON.parse(sendRESTRequest(commandToURL[command] ,args));
}

args.sessionId = sendAndParse('ConnectRequest', {username: username, password: password}, 'AFA');
res = JSON.parse(x2j(sendAndParse(commandToMethod[command], args)));
sendAndParse('DisconnectRequest', {sessionId: args.sessionId}, 'AFA');
return res;
