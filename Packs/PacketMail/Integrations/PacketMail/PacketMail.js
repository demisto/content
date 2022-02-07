var initialurl = params.url;
var malLists = params.maliciousList.split(',');
for (i = 0 ; i < malLists.length; i++) {
    malLists[i] = malLists[i].trim();
}

var sendRequest = function(url, param) {

    // handle '/' at the end of the url
    if (url[url.length - 1] === '/') {
        url = url.substring(0, url.length - 1);
    }

    var res = http(
        url,
        {
            Method: 'GET',
            Headers: {
                Accept: ['application/json']
            }
        },
        params.insecure,
        params.proxy
    );

    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        throw 'Request Failed.\nStatus code: ' + res.StatusCode + '.\nBody: ' + JSON.stringify(res) + '.';
    }

    try {
      return JSON.parse(res.Body);
    } catch (err) {
        throw 'Invalid response - expected JSON and got ' + res.Body;
    }
};

// The command input arg holds the command sent from the user.
switch (command) {
    // This is the call made when pressing the integration test button.
    case 'test-module':
        res = sendRequest(initialurl + '8.8.8.8' + '?apikey='+params.apikey);
        if (res.query_result === 'Success') {
            return 'ok';
        }
        return res;
    case 'packetmail-ip':
        var res =  sendRequest(initialurl + args.ip + '?apikey='+params.apikey);
        md = '';
        maliciousLists = '';
        var keys = Object.keys(res);
        keys = keys.sort();
        for (i = 0 ; i < keys.length; i++) {
            if (md.length > 0) {
                md += '\n\n';
            }
            if (res[keys[i]] instanceof Object) {
                if (malLists.indexOf(keys[i]) >= 0) {
                    if (maliciousLists.length > 0) {
                        maliciousLists += ',';
                    }
                    maliciousLists += keys[i];
                }
                md += tableToMarkdown(keys[i], res[keys[i]]);
            }
        }
        ec = {};
        if (maliciousLists. length > 0) {
            addMalicious(ec, outputPaths.ip,{
                    Address: args.ip,
                    Malicious: {Vendor: 'PacketMail', Description: 'Found in malicious lists: ' + maliciousLists}});
        }
        return {Contents: res, HumanReadable: md, ContentsFormat: formats.json, Type: entryTypes.note, EntryContext: ec};
}

