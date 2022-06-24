var sendRequest = function(method, url, body) {
    var res = http(url,
        {
            Method: method,
            Body: body,
            Headers: {'Content-Type': ['application/x-www-form-urlencoded']},
            Username: params.sid,
            Password: params.token
        },
        params.insecure,
        params.proxy
    );
    if (res.StatusCode < 200 || res.StatusCode >=300) {
        throw 'Request Failed.\nStatus code: ' + res.StatusCode + '.\nBody: ' + JSON.stringify(res.Body) + '.';
    }
    return res.Body;
};

String.prototype.formatWithValues = function(values) {
    var formattedString = this;
    var regexIterator = this.matchAll('\{(.*?)\}');
    if (regexIterator.length === 0) { return this; }
    if (regexIterator.length != values.length) { return this; }
    for (var elem of regexIterator) {
        formattedString = replaceString(formattedString, elem[0], values[Number(elem[1])]);
    }
    return formattedString;
};

String.prototype.matchAll = function(regex) {
    var tempString = this;
    const matches = [];
    var match = tempString.match(regex);
    while (match !== null) {
        matches.push(match);
        tempString = replaceString(tempString, match[0], "");
        match = tempString.match(regex);
    }
    return matches;
}

function replaceString(string, valueToReplace, newValue) {
    return string.substring(0, string.indexOf(valueToReplace)) + newValue + string.substring(string.indexOf(valueToReplace) + valueToReplace.length, string.length);
}

var encodeToURLQuery = function(to, from, body){
    return "From="+encodeURIComponent('+'+from.replace(/^\+/, ''))+"&To="+encodeURIComponent('+'+to.replace(/^\+/, ''))+"&Parameters="+encodeURIComponent(body);
};

switch (command) {
    // This is the call made when pressing the integration test button.
    case 'test-module':
        // from Twilio instructions, in order to ger the list of accounts, the below curl command should be used.
        // using this as a method to test that the credentials and connectivity are good, without using sms buckets
        // curl -G https://api.twilio.com/2010-04-01/Accounts -u '[YOUR ACCOUNT SID]:[YOUR AUTH TOKEN]'
        sendRequest('GET', "https://api.twilio.com/2010-04-01/Accounts", "");
        return 'ok';
    case 'emergency-call':

        var ttsMessageArgs = [];
        if (args.ttsMessageArgs) {
            if (args.ttsMessageArgs.indexOf(",") == -1) {
                ttsMessageArgs.push(args.ttsMessageArgs);
            } else {
               ttsMessageArgs = args.ttsMessageArgs.split(",");
            }
        }

        ttsMessage = args.ttsMessage.formatWithValues(ttsMessageArgs);

        body = {
            "incidentID": args.incident_id,
            "assignee": args.assignee,
            "ttsMessage": ttsMessage
        }

        sendRequest('POST', params.server+params.flow_id+'/Executions', encodeToURLQuery(args.to, (args.from ? args.from : params.from), JSON.stringify(body)));
        return 'Call request sent successfully!';
}

