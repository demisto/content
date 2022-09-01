var excludedIps;
if (args.excludedIps) {
    excludedIps = args.excludedIps.split(',');
}
var flat = {};
var res = [];
var currentValue;
flattenFields(invContext,undefined,flat);
keysArr = Object.keys(flat);
for (var i = 0; i < keysArr.length; i++) {
    currentValue=flat[keysArr[i]];
    if (ipRegex.test(currentValue) && res.indexOf(currentValue) === -1) {
        if (excludedIps) {
            if (excludedIps.indexOf(currentValue) === -1) {
                res.push(currentValue);
            }
        } else {
            res.push(currentValue);
        }
    }
}

var md = '### IP addresses in context\n';
for (var i = 0; i<res.length; i++) {
    md += '- ' + res[i] + '\n';
}
return {
        Type: entryTypes.note,
        Contents: res,
        ContentsFormat: formats.json,
        HumanReadable: md
        };

