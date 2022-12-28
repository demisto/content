var body = {
    id: args.masterID,
    otherIncidentsIDs: args.otherIDs.split(','),
    removeLink: (args.unlink === 'yes')
};

var res = executeCommand('demisto-api-post', {uri: '/incident/links', body: body});

if (isError(res[0])) {
    throw res[0].Contents;
}

var response = res[0].Contents.response;
var md = tableToMarkdown('Demisto link incidents', response);

return {
    ContentsFormat: formats.json,
    Type: entryTypes.note,
    Contents: response,
    HumanReadable: md
};
