var rows = args.rows ? args.rows : 30;
var query = (args.query.indexOf('|') > 0) ? args.query : args.query + ' | head ' + rows;

var res = executeCommand('search', {'using-brand': 'splunk', query: query});
var table = {
    Type: 1,
    ContentsFormat: 'table',
    Contents: []
};

for (var i=0; i<res[0].Contents.length; i++) {
    data = res[0].Contents[i].result['_raw'];
    table.Contents.push({Time: res[0].Contents[i].result['_time'], Host: res[0].Contents[i].result['host'], Source: res[0].Contents[i].result['source'], Data: data});
}
return table;
