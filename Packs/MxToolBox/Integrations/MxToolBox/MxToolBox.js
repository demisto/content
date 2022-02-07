var doReq = function(cmd, data, p) {
    var url = 'https://api.mxtoolbox.com/api/v1/lookup/' + cmd + '/' + data;
    if (p) {
        url += '?' + p;
    }
    var result = http(
        url,
        {
            Headers: {'Accept': ['application/json'], 'Authorization': [params.apiKey]},
            Method: 'GET'
        },
        params.insecure,
        params.useproxy
    );

    if (result.StatusCode < 200 || result.StatusCode > 299) {
        throw 'Failed to perform command "' + cmd + '", request status code: ' + result.StatusCode +
            ' body is: ' + result.Body;
    }
    if (result.Body === '') {
        throw 'No content received for command "' + cmd + '", request status code: ' + result.StatusCode;
    }
    var obj;
    try {
        obj = JSON.parse(result.Body);
    } catch (ex) {
        throw 'Error parsing reply - ' + result.Body + ' - ' + ex;
    }
    return {body: result.Body, obj: obj, statusCode: result.StatusCode};
};

switch (command) {
    case 'test-module':
        doReq('mx', 'example.com');
        return 'ok';
    case 'mxtoolbox':
        var res = doReq(args.command, args.data, args.additionalParams);
        var ec = {};
        var md = 'MxToolbox command - **' + args.command + '**\n';
        var arrays = ['Passed', 'Failed', 'Errors', 'Warnings', 'Information', 'MultiInformation', 'Transcript'];
        for (var i=0; i<arrays.length; i++) {
            if (res.obj[arrays[i]] && res.obj[arrays[i]].length > 0) {
                md += tableToMarkdown(arrays[i], res.obj[arrays[i]]) + '\n';
                ec['MXToolbox.' + arrays[i]] = res.obj[arrays[i]];
            }
            delete res.obj[arrays[i]];
        }
        delete res.obj.RelatedLookups;
        md += tableToMarkdown('Result Data', res.obj);
        ec['MXToolbox.Data'] = res.obj;
        return {Type: entryTypes.note, Contents: res.body, ContentsFormat: formats.json, HumanReadable: md, EntryContext: ec};
    default:
        throw 'Unknown command ' + command + ' requested';
}
