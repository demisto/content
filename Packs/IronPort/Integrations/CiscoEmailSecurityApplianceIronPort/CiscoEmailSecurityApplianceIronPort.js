var host = params.server.replace(/[\/]+$/, '') + ':'+params.port;

var sendRequest = function(url, method) {
    var res = http(
        url,
        {
            Method: method,
            Headers: {
                Accept: ['application/json'],
                Host: [host]
            },
            Username: params.credentials.identifier,
            Password: params.credentials.password
        },
        params.insecure,
        params.proxy
    );
    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        throw 'Request Failed.\nStatus code: ' + res.StatusCode + '.\nBody: ' + JSON.stringify(res) + '.';
    }
    return res;
};

var underscoreToCapital = function(string){
    var ret_string = '_'+string;
    return ret_string.replace(/_([a-z])/g, function (g) { return ' '+g[1].toUpperCase(); });
};

var convertResKeys = function(res){
    var ret = {};
    var keys = Object.keys(res);
    keys.forEach(function(key){
        ret[underscoreToCamelCase(key)] = res[key];
    });
    return ret;
};

function getReport(command, args){
    delete args.report_type;
    requestURL = host+'/api/v1.0/stats/'+command;

    var time_range = args.time_range;
    delete args.time_range;
    var attributes = encodeToURLQuery(args);

    if(time_range){
        attributes += (attributes.length > 0) ? '&'+time_range : '?' + time_range;
    }
    else if(!args.duration){
            throw 'Time range missing. Must provide either time_range or duration arguments.';
    }
    rawResponse = sendRequest(requestURL + attributes, 'GET');
    try{
        res = JSON.parse(rawResponse.Body).data;
    }
    catch (err){
        return rawResponse;
    }
    context = {};
    context['IronPort.'+underscoreToCamelCase(command)] = convertResKeys(res);
    return {
        Type: entryTypes.note,
        Contents: res,
        ContentsFormat: formats.json,
        ReadableContentsFormat : formats.markdown,
        EntryContext : context,
        HumanReadable: tableToMarkdown('IronPort Report', res, undefined, undefined, underscoreToCapital)
    };
}

switch (command) {
    case 'test-module':
        res = getReport('mail_authentication_summary', {time_range: '1d'});
        if(!res.Contents){
            return res;
        }
        return 'ok';
    default:
        return getReport(args.report_type, args);
}
