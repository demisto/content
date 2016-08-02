var queryLimit = '100';
if (args.limit) {
    queryLimit = args.limit;
}

var ip = args.ip;

var filters = '[{  "type": "EsmFieldFilter",  "field": {"name": "SrcIP"},  "operator": "EQUALS",   "values": [{  "type": "EsmBasicValue",    "value": "'+ip+'"  }]  }]';

return executeCommand('search', {'using-brand': 'esm', limit: queryLimit, filters: filters, 'time_range': 'CURRENT_YEAR', fields: 'Alert.ID,Alert.LastTime'});
