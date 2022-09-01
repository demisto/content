var entryRes = executeCommand('getEntry', {'id': args.humanReadableEntryId});
if (entryRes && Array.isArray(entryRes)) {
    if (entryRes[0].Type !== entryTypes.error) {
        var outputString = entryRes[0].Contents;
    }
} else {
    throw 'Unexpected entry result: {0}'.format(entryRes);
}

if (outputString.indexOf(args.substring) == -1) {
    throw 'Output string does not contain the expected substring.\n\nOutput string:\n{0}\nSubstring:\n{1}'.format(outputString, args.substring);
}

log('Output string contains the given substring: {0}'.format(args.substring));
