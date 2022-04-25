var sendRequest = function(method, url, body) {
    var res = http(
        params.server.replace(/[\/]+$/, '')+'/'+params.sid+'/Messages.json',
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

var encodeToURLQuery = function(to, from, body){
    return "From="+encodeURIComponent('+'+from.replace(/^\+/, ''))+"&To="+encodeURIComponent('+'+to.replace(/^\+/, ''))+"&Body="+encodeURIComponent(args.body);
};

switch (command) {
    // This is the call made when pressing the integration test button.
    case 'test-module':
        // from Twilio instructions, in order to ger the list of accounts, the below curl command should be used.
        // using this as a method to test that the credentials and connectivity are good, without using sms buckets
        // curl -G https://api.twilio.com/2010-04-01/Accounts -u '[YOUR ACCOUNT SID]:[YOUR AUTH TOKEN]'
        sendRequest('GET', params.server.replace(/[\/]+$/, ''), "");
        return 'ok';
    default:
        sendRequest('POST', params.server.replace(/[\/]+$/, '')+'/'+params.sid+'/Messages.json', encodeToURLQuery(args.to, (args.from ? args.from : params.from), args.body));
        return 'Message sent successfully!';
}

