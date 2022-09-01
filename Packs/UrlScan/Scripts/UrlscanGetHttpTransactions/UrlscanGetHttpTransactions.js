var url = args.url;
var limit = args.limitl;
var defaultWaitTime = Number(args.wait_time_for_polling)

uuid = executeCommand('urlscan-submit-url-command', {'url': url})[0].Contents;
uri = executeCommand('urlscan-get-result-page', {'uuid': uuid})[0].Contents;

var resStatusCode = 404
var waitedTime = 0
while(resStatusCode == 404 && waitedTime < Number(args.timeout)) {
    var resStatusCode = executeCommand('urlscan-poll-uri', {'uri': uri})[0].Contents;

    if (resStatusCode == 200) {
        break;
    }
    wait(defaultWaitTime);
    waitedTime = waitedTime + defaultWaitTime;
}
if(resStatusCode == 200) {
    return executeCommand('urlscan-get-http-transaction-list', {'uuid': uuid, 'url': url, 'limit': limit});
} else {
    if(waitedTime >= Number(args.timeout)){
        return 'Could not get result from UrlScan, please try to increase the timeout.'
    } else {
        return 'Could not get result from UrlScan, possible rate-limit issues.'
    }
}
