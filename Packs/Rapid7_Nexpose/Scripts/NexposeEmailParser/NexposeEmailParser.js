var entries = executeCommand('getEntries', {});
var report = 0;
if (!args.entryID) {
    for (var i = 0; i < entries.length; i++) {
        if (entries[i].File) {
            var entryIDFromInv = entries[i].ID;
            report = getFileByEntryID(entryIDFromInv);
            if (/$<NexposeReport/.exec(report)) {
                break;
            }
        }
    }
} else {
    report = getFileByEntryID(args.entryID);
}
var contents = [];
var nodes = report.split(/<\/node>/);
for (var i=0; i < nodes.length; i++) {
    var nodeRegexp = /<node address="(.*)" status="(.*)" device-id="(.*)" site-name="(.*)" site-importance="(.*)" scan-template=".*" risk-score="(.*)">/g;
    var match = nodeRegexp.exec(nodes[i]);
    if (nodes[i] && match) {
        var testRegexp = /<test id=.*>/g ;
        var vulnCount = nodes[i].match(testRegexp) ? nodes[i].match(testRegexp).length : '0';
        var data = {
            Address: match[1],
            Name: match[4],
            Risk: match[6],
            Status: match[2],
            Importance: match[5],
            Vulnerabilities: vulnCount
        };
        if ((args.minRiskScore && args.minRiskScore <= data.Risk) || !args.minRiskScore) {
            if ((args.minVulnCount && args.minVulnCount <= data.Vulnerabilities) || !args.minVulnCount) {
                contents.push(data);
                var sev = "low";
                if (data.Risk > 3000) {
                    sev = "critical";
                } else if (data.Risk > 2500) {
                    sev = "high";
                } else if (data.Risk > 2000) {
                    sev = "medium";
                }
                createNewIncident({
                                  type: 'Nexpose alert',
                                  details: nodes[i],
                                  severity: sev,
                                  name: data.Address + ' vulnerability count ' + data.Vulnerabilities + ' risk score ' + data.Risk,
                                  systems: data.Address
                              });
            }
        }
    }
}
return [{Contents: contents,
         ContentsFormat: formats.table,
         Type: entryTypes.note},
         closeInvestigation({Reason: 'Spawned ' + contents.length + ' child incidents'})];
