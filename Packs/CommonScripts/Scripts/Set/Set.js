var ec = {};
var value;
try {
    if (args.stringify === 'true') {
        if (typeof args.value === 'string') {
            value = args.value
        } else {
            value = JSON.stringify(args.value)
        }
    } else {
        value = JSON.parse(args.value);
    }
} catch (err) {
    value = args.value;
}
logDebug(`Got the args object ${JSON.stringify(args)}`)
logDebug('Got the value ' + value)
logDebug('Will insert the value to the key ' + args.key)
ec[args.key] = value;
var result = {
    Type: entryTypes.note,
    Contents: ec,
    ContentsFormat: formats.json,
    HumanReadable: 'Key ' + args.key + ' set'
};

if (!args.append || args.append === 'false') {
    setContext(args.key, value);
} else {
    result.EntryContext = ec;
}
logDebug(`The final result object ${JSON.stringify(result)}`)
return result;
