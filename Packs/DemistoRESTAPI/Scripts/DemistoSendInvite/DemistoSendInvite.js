var res = executeCommand('demisto-api-get', {uri: '/roles'});
if (isError(res[0])) {
    throw res[0].Contents;
}

var roles = res[0].Contents.response;
var roleIDs = [];
var roleNames = args.roles.split(',');

roleNames.forEach(function(roleName) {
    var roleID = dq({roles:roles},'roles(val.name=="'+roleName+'").id');
    if (!roleID) {
        throw 'Cannot find role ' + roleName;
    }
    roleIDs.push(roleID[0]);
});

body = {
    email: args.email,
    roles: roleIDs
};

res = executeCommand('demisto-api-post', {uri: '/invite', body: body});
if (isError(res[0])) {
    throw res[0].Contents;
}

var response = res[0].Contents.response;
var md = tableToMarkdown('Demisto invite user', response);
var ec = {email: response.email, link: response.url};

return {
    ContentsFormat: formats.json,
    Type: entryTypes.note,
    Contents: response,
    HumanReadable: md
};
