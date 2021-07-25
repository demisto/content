var wisdomURL = 'https://api.alphasoc.net/v1/wisdom'

var sendRequest = function(requestUrl) {
    var res = http(
        requestUrl,
        {
            Method: 'GET',
            Headers: {
                Authorization: ['Basic ' + btoa(params.APIKey + ':')],
                Accept: ['application/json']
            }
        },
        params.insecure,
        params.proxy
    );

    if (!res || res.StatusCode < 200 || res.StatusCode >= 300) {
        var errorString = '';

        if (res.StatusCode === 401 || res.StatusCode === 403) {
            errorString = '\n\nError: Invalid API key\n';
        }

        errorString += '\nRequest Failed'
            + '\nRequestUrl: ' + requestUrl
            + '\nStatus code: ' + res.StatusCode
            + '\nResponse: ' + JSON.stringify(res);
        throw errorString;
    }

    try {
        return JSON.parse(res.Body);
    } catch (err) {
        throw 'Failed to parse JSON response: ' + res.Body + '\n';
    }
};

var extractDomainName = function(url) {
    var hostname;

    //find & remove protocol (http, ftp, etc.) and get the hostname
    if (url.indexOf("://") > -1) {
        hostname = url.split('/')[2];
    }
    else {
        hostname = url ? url.split('/')[0] : '';
    }

    //find & remove port number
    hostname = hostname.split(':')[0];

    return hostname;
}

var getDomainWisdom = function(domain) {
    var extractedDomain = extractDomainName(domain);
    var url = wisdomURL + '?q=' + extractedDomain;
    var result = sendRequest(url);

    var ec = {
        Domain: {Name: extractedDomain},
        Wisdom: {Flag: result.flags}
    }

    var md = '#### AlphaSOC Wisdom Flags for __' + extractedDomain + '__\n';

    if (result.flags.length === 0) {
        md += '__No flags.__\n';
    } else {
        for (var i = 0; i < result.flags.length; i++) {
            md += '- ' + result.flags[i] + '\n';
        }
    }

    return {
        Type: entryTypes.note,
        EntryContext: ec,

        ContentsFormat: formats.json,
        Contents: result,

        ReadableContentsFormat: formats.markdown,
        HumanReadable: md
    };
}

var getIPWisdom = function(proto, ip, port) {
    var escapedIP = ip.indexOf(':') > 0 ? '[' + ip + ']' : ip;
    var query = proto + ':' + escapedIP + ':' + port;
    var url = wisdomURL + '?q=' + query;
    var result = sendRequest(url);

    var ec = {
        Wisdom: {Flag: result.flags}
    }

    var md = '#### AlphaSOC Wisdom Flags for __' + query + '__\n';

    if (result.flags.length === 0) {
        md += '__No flags.__\n';
    } else {
        for (var i = 0; i < result.flags.length; i++) {
            md += '- ' + result.flags[i] + '\n';
        }
    }

    return {
        Type: entryTypes.note,
        EntryContext: ec,

        ContentsFormat: formats.json,
        Contents: result,

        ReadableContentsFormat: formats.markdown,
        HumanReadable: md
    };
}

// The command input arg holds the command sent from the user.
switch (command) {
    // This is the call made when pressing the integration test button.
    case 'test-module':
        getDomainWisdom('example.com');
        return 'ok';
    case 'wisdom-domain-flags':
        return getDomainWisdom(args.domain);
    case 'wisdom-ip-flags':
        return getIPWisdom(args.proto, args.ip, args.port)
    default:
}
