var report = args.report ? args.report : incidents[0].details;
var contents = {};
var nodes = report.split(/<\/node>/);
for (var i=0; i < nodes.length; i++) {
    var nodeRegexp = /<node address="(.*)" status="(.*)" device-id="(.*)" site-name="(.*)" site-importance="(.*)" scan-template="(.*)" risk-score="(.*)">/g;
    var vulnRegexp = /(<test id="(.*)" key="(.*)" status="(.*)" scan-id="(.*)" vulnerable-since="(.*)" pci-compliance-status="fail">)/g;
    var res = nodes[i].match(/(<test .*>)/g);
    var match = nodeRegexp.exec(nodes[i]);
    if (nodes[i] && match) {
        var vulnCount = nodes[i].match(vulnRegexp) ? nodes[i].match(vulnRegexp).length : '0';
        var data = {
                Address: match[1],
                Name: match[4],
                Risk: match[6],
                Status: match[2],
                Importance: match[5],
                Vulnerabilities: vulnCount
            };
        for (var j = 0; res && j < res.length; j++) {
            var current = vulnRegexp.exec(res[j]);
            if (current) {
                if (contents[current[2]]) {
                    contents[current[2]].labels.push(data);
                } else {
                    contents[current[2]] = {labels: [], Name: current[2]};
                }
            }
        }
    }
}
var k = 0;
for (var key in contents) {
    var element = contents[key];
    var labels = '';
    for (var j = 0; j < element.labels.length; j++) {
                labels += element.labels[j].Address + ',';
            }
    labels = labels.slice(0, -1);
    if (labels.length > 0) {
        createNewIncident({
                                      type: 'Nexpose alert',
                                      details: JSON.stringify(element.labels),
                                      severity: args.defaultNexposeSeverity,
                                      name: key,
                                      systems: labels
                                  });
    }
}
return closeInvestigation({Reason: 'Spawned ' + k + ' child incidents'});
