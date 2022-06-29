//replace all occurences of textToReplace with replaceWith string
String.prototype.replaceAll = function(textToReplace,replaceWith) {
    return this.split(textToReplace).join(replaceWith);
};

// get a specific label from incident labels
var getLabel = function(incident,path) {
    label = path.split('.')[2];
    for (var i=0; i<incident.labels.length; i++) {
        if (incident.labels[i].type == label) {
            return incident.labels[i].value;
        }
    }
    return null;
};

var res = executeCommand("getList", {"listName": args.listTemplate});

if (res[0].Type == entryTypes.error) {
    return res;
}

// Finding all placeholders and creating a map with values
var html = res[0].Contents;
var reg = /\${(.+?)}/g;
var map = {};

while (found = reg.exec(html)) {
    var path = found[1];

    if (path.indexOf('incident.labels.') === 0) {
        map[path] = getLabel(incidents[0], path);
    } else if (path.indexOf('incident.') === 0) {
        map[path] = dq({'incident': incidents[0]}, path);
        // check if this path is actually in custom fields
        if (!map[path]) {
            var customFieldPath = path.replace('incident.', 'incident.CustomFields.');
            map[path] = dq({'incident': incidents[0]}, customFieldPath);
        }
    } else if (path.indexOf('object.') === 0) {
        var obj = (typeof args.object === 'string') ? JSON.parse(args.object) : args.object;
        map[path] = dq({'object': obj}, path);
    } else {
        map[path] = dq(invContext, path);
    }
}

// replacing all placeholders with values
for (var path in map) {
    // if value found replace. Otherwise will leave placeholder
    if (map[path]) {
        html = html.replaceAll('${' + path + '}', map[path]);
    } else if (args.removeNotFound === 'yes') {
        html = html.replaceAll('${' + path + '}', '');
    }
}

// setting to contesxt so it override an oder entry if there is (using EntryContext in the returned object only append)
setContext(args.key,html);

return {
    ContentsFormat: formats.json,
    Type: entryTypes.note,
    Contents: {htmlBody: html},
    HumanReadable: 'htmlBody set to context key ' + args.key
};
