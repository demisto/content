var res = executeCommand("getIncidents", {
    'query': 'status:closed and investigation.users:""',
    'fromdate': args.from,
    'todate': args.to,
    'size': 0
});
var closedByDbot = res[0].Contents.total;

res = executeCommand("getIncidents", {
    'status': 'closed',
    'fromdate': args.from,
    'todate': args.to,
    'size': 0
});
var overallClosed = res[0].Contents.total;

var result = Math.round(closedByDbot * 100 / overallClosed);
return isNaN(result) ? 0 : result;
