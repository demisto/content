var ec = {};
var value;
try {
    if (args.stringify === 'true' ) {
        if (typeof args.value === 'string') {
            value = args.value
        } else {
            value = JSON.stringify(args.value)
        }
    } else {
        if (!isNaN(args.value) && !args.value.includes('.') && args.value >= Number.MAX_SAFE_INTEGER) {
            value = BigInt(args.value);
        }
        else {
            value = JSON.parse(args.value);
        }
    }
} catch (err) {
    value = args.value;
}
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
logDebug(`Setting ${JSON.stringify(result)}`)
return result;
