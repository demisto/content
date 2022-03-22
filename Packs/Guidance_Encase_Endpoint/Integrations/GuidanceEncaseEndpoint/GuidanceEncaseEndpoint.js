var url = params.server + ":" + params.port + "/GenericListener/Handler";

var sendRequest = function(xml) {
    var result =  http(url,
                {
                    Headers: {'Content-Type': ['application/xml;charset=utf-8']},
                    Method: 'POST',
                    Body:xml
                },
                params.insecure,
                params.proxy
            );
    // return result;
    if (result.StatusCode !== 200) {
        throw  'Failed to encase-run-job, request status code: ' + result.StatusCode + ', body: ' + result.Body;
    }
    return result;
};

// The command input arg holds the command sent from the user.
switch (command) {
    // This is the call made when pressing the integration test button.
    case 'test-module':
        if (sendRequest()) {
            return 'ok';
        }
        return 'something is wrong';
    case 'encase-copyjob':
        var requestXML =
            '<TASK>\
                <FUNCTION>copy cyber job</FUNCTION>\
                <INVESTIGATION>\
                    <DATA-STORE-NAME>%case%</DATA-STORE-NAME>\
                    <INVESTIGATION-NAME>%investigationName%</INVESTIGATION-NAME>\
                </INVESTIGATION>\
                <DATA>\
                    <SAFE-NAME>%safeName%</SAFE-NAME>\
                    <CUSTODIAN-NAME>%custodianName%</CUSTODIAN-NAME>\
                    <EXISTING-JOB-NAME>%jobName%</EXISTING-JOB-NAME>\
                    <MACHINE-ADDRESSES>\
                        <MACHINE-IP-RANGE>%machineIPs%</MACHINE-IP-RANGE>\
                    </MACHINE-ADDRESSES>\
                    <EVENT-NAME>%eventName%</EVENT-NAME>\
                    <EVENT-ID>%eventId%</EVENT-ID>\
                </DATA>\
            </TASK>';
        var result = sendRequest(replaceInTemplates(requestXML,
            {
                case: args.case,
                jobName: args["existing-job-name"],
                investigationName: args["investigation-name"],
                machineIPs: args["machine-ips"],
                safeName: args["safe-name"],
                custodianName: args["custodian-name"],
                eventName: args["event-name"],
                eventId: args["event-id"]
            }));
        return JSON.parse(x2j(result.Body)).task.message;
   case 'encase-snapshot':
       var requestXML =
            '<TASK>\
                <FUNCTION>snapshot</FUNCTION>\
                <INVESTIGATION>\
                    <DATA-STORE-NAME>%case%</DATA-STORE-NAME>\
                    <INVESTIGATION-NAME>%investigationName%</INVESTIGATION-NAME>\
                </INVESTIGATION>\
                <DATA>\
                    <SAFE-NAME>%safeName%</SAFE-NAME>\
                    <CUSTODIAN-NAME>%custodianName%</CUSTODIAN-NAME>\
                    <MACHINE-ADDRESSES>\
                        <MACHINE-IP-RANGE>%machineIPs%</MACHINE-IP-RANGE>\
                    </MACHINE-ADDRESSES>\
                   <JOB-NAME>%jobName%</JOB-NAME>\
                </DATA>\
            </TASK>';
        var result = sendRequest(replaceInTemplates(requestXML,
            {
                case: args.case,
                investigationName: args["investigation-name"],
                machineIPs: args["machine-ips"],
                safeName: args["safe-name"],
                custodianName: args["custodian-name"],
                jobName: args["job-name"]
            }));
        return JSON.parse(x2j(result.Body)).task.message;
    case 'encase-verifyhash':
        var requestXML =
            '<TASK>\
                <FUNCTION>verify hash</FUNCTION>\
                <SOURCE-NAME>%sourceName%</SOURCE-NAME>\
                <INVESTIGATION>\
                    <DATA-STORE-NAME>%case%</DATA-STORE-NAME>\
                    <INVESTIGATION-NAME>%investigationName%</INVESTIGATION-NAME>\
                </INVESTIGATION>\
                <DATA>\
                    <SAFE-NAME>%safeName%</SAFE-NAME>\
                    <CUSTODIAN-NAME>%custodianName%</CUSTODIAN-NAME>\
                    <MACHINE-ADDRESSES>\
                        <MACHINE-IP-RANGE>%machineIPs%</MACHINE-IP-RANGE>\
                    </MACHINE-ADDRESSES>\
                    <HASH-SET>\
                      <HASH>\
                        <FILE-NAME>%fileName%</FILE-NAME>\
                        <FILE-SIZE>%fileSize%</FILE-SIZE>\
                        <CONTENT-HASH>%contentHash%</CONTENT-HASH>\
                      </HASH>\
                    </HASH-SET>\
                </DATA>\
            </TASK>';
        var result = sendRequest(replaceInTemplates(requestXML,
            {
                case: args.case,
                sourceName: args["source-name"],
                investigationName: args["investigation-name"],
                machineIPs: args["machine-ips"],
                safeName: args["safe-name"],
                custodianName: args["custodian-name"],
                fileName: args["file-name"],
                fileSize: args["file-size"],
                contentHash: args["content-hash"]
            }));
        return JSON.parse(x2j(result.Body)).task.message;

    default:
        // You can use args[argName] or args.argName to get a specific arg. args are strings.
        // You can use params[paramName] or params.paramName to get a specific params.
        // Params are of the type given in the integration page creation.
}
