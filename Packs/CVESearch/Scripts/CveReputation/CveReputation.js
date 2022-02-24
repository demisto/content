var resCmd = executeCommand('cve', {'cve_id': args.input});
var maxTries = 5;
var counter = 0;
while (isError(resCmd) && counter < maxTries) {
    resCmd = executeCommand('cve', {'cve_id': args.input});
    counter++;
}

if (isError(resCmd)) {
    throw resCmd.Contents;
}

results = []; for (i=0; i < resCmd.length && resCmd[i].Contents; i++) {
    var data = resCmd[i].Contents;

    var key = Object.keys(resCmd[i].EntryContext)[0]

    var cvss = (data.cvss) ? parseInt(data.cvss) : -1;

    var res;

    if (cvss === -1) {
        res = 0;
    } else if (cvss < 3) {
        res= 1;
    } else if (cvss < 7) {
        res= 2;
    } else {
        res= 3;
    }
    results.push(
        {
            Type: entryTypes.note,
            Contents: res,
            HumanReadable: res,
            EntryContext:{'CVE':resCmd[i].EntryContext[key]}
        }
    )
}
if (results.length === 0) {
    // resCmd is expected to be empty result
    return resCmd;
} return results;
