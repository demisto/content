function addEntry(text) {
    entry =  [{ContentsFormat: formats.markdown, Type: entryTypes.note, Contents: text}];
    executeCommand("addEntries", {"entries":JSON.stringify(entry)});
}

var account = incidents[0].account ?  'acc_' + incidents[0].account : "";

var res = executeCommand("getUsers", {current: true});
if (isError(res[0])) {
    return { ContentsFormat: formats.text, Type: entryTypes.error, Contents: 'Cannot get current user.\nThis script cannot be executed within a playbook.' };
}

var username = res[0].Contents[0].username;

res = executeCommand("getIncidents", {query: 'investigation.users:"'+username+'" and status:Active and -owner:"'+username+'"', size: 10000});
if (isError(res[0])) {
    return res;
}

var ids = dq(res[0].Contents.data,'id');
var errors = [];

if (ids && ids.length > 0) {
    ids.forEach(function(id) {
        var uri = account + '/investigation/' + id + '/deleteuser/' + username;
        addEntry('Leaving investigation ' + id + '...');
        var res = executeCommand('demisto-api-post', {uri: uri, body: {}});
        if (isError(res[0])) {
            errors.push(res[0]);
        }
    });
}
return (errors.length === 0) ? 'Done' : errors;
