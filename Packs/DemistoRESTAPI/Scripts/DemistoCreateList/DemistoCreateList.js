var body = {
    name: args.listName,
    data: args.listData,
};

var res = executeCommand('demisto-api-post', {uri: '/lists/save', body: body});

if (isError(res[0])) {
    throw res[0].Contents;
}

var response = res[0].Contents.response;
var md = tableToMarkdown('Demisto create list', response);

return {
    ContentsFormat: formats.json,
    Type: entryTypes.note,
    Contents: response,
    HumanReadable: md
};
