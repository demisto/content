var macAddressRegex = new RegExp("^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")
var excludedMACAddress;
if (args.excludedMACAddress) {
    excludedMACAddress = args.excludedMACAddress.split(',');
}
var flat = {};
var res = [];
var currentValue;
flattenFields(invContext,undefined,flat);
keysArr = Object.keys(flat);
for (var i = 0; i < keysArr.length; i++) {
    currentValue=flat[keysArr[i]];
    if (macAddressRegex.test(currentValue) && res.indexOf(currentValue) === -1) {
        if (excludedMACAddress) {
            if (excludedMACAddress.indexOf(currentValue) === -1) {
                res.push(currentValue);
            }
        } else {
            res.push(currentValue);
        }
    }
}

var md = '### MAC addresses in context\n';
for (var i = 0; i<res.length; i++) {
    md += '- ' + res[i] + '\n';
}
return {
        Type: entryTypes.note,
        Contents: res,
        ContentsFormat: formats.json,
        HumanReadable: md
        };
