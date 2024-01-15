var ec = {};
var value;
logDebug(`Got the args object ${JSON.stringify(args)}`)
try {
    if (args.stringify === 'true') {
        if (typeof args.value === 'string') {
            value = args.value
        } else {
            value = JSON.stringify(args.value)
        }
    } else {
        if (!isNaN(args.value)) {
            // This means that the value is a number in string representation
            if (args.value.includes('.')) {
                // It is a decimal number
                value = JSON.parse(args.value);
            }
            else {
                // If the number is large
                value = BigInt(args.value);
            }
        }
        else {
            value = JSON.parse(args.value);
        }
    }
} catch (err) {
    value = args.value;
}
logDebug('Got the value ' + value)
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
