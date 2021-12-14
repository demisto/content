var base = params.server.replace(/[\/]+$/, '') + '/api/' + params.version + '/';

var commands = {
    'cloudlock-get-users': {
        url: 'users',
        method: 'GET',
        extended: true,
        title: 'CloudLock get users response',
        contextPath: 'CloudLock.Users(val.ID==obj.ID)',
        translator: [
            {to: 'ID', from: 'id'},
            {to: 'Name', from: 'name'},
            {to: 'Suspended', from: 'suspended'},
            {to: 'Email', from: 'email'},
            {to: 'OU', from: 'ou'},
            {to: 'Incidents-Total', from: 'total_incidents'},
            {to: 'Incidents-Active', from: 'total_active_incidents'},
            {to: 'Entities-Total', from: 'total_entities'},
            {to: 'Entities-Exposed', from: 'total_exposed_entities'},
        ]
    },
    'test-module': {
        url: 'users',
        method: 'GET',
        defaultArgs: {
            limit: 1
        }
    },
    'cloudlock-get-user-apps': {
        url: 'users/%email%/apps',
        method: 'GET',
        extended: true,
        title: 'CloudLock get user apps response',
        contextPath: 'CloudLock.Users(val.Email==obj.Email)',
        translator: [
            {to: 'Applications-Category', from: 'app.category'},
            {to: 'Applications-AccessRisk', from: 'app.access_risk'},
            {to: 'Applications-RiskLevel', from: 'app.risk_level'},
            {to: 'Applications-ID', from: 'app.risk_level'},
            {to: 'Applications-Name', from: 'app.name'},
            {to: 'Applications-Vendor', from: 'app.id'},
        ]
    },
    'cloudlock-get-activities': {
        url: 'activities',
        method: 'GET',
        extended: true,
        innerPath: 'items',
        title: 'CloudLock get activities response',
        contextPath: 'CloudLock.Activities(val.ID==obj.ID)',
        translator: [
                {to: 'ID', from: 'event_id'},
                {to: 'IP', from: 'client_ip'},
                {to: 'Type', from: 'event_type'},
                {to: 'Created', from: 'created_at'},
                {to: 'Successful', from: 'operation_successful'},
                {to: 'Location-Latitude', from: 'client_location.lat'},
                {to: 'Location-Longitude', from: 'client_location.lng'},
                {to: 'Location-Country-Code', from: 'client_location.country.code'},
                {to: 'Location-Country-Name', from: 'client_location.country.name'},
                {to: 'Location-Region-Code', from: 'client_location.region.code'},
                {to: 'Location-Region-Name', from: 'client_location.region.name'},
                {to: 'Location-City', from: 'client_location.city'},
                {to: 'Category', from: 'event_category'},
                {to: 'OriginID', from: 'origin_id'},
                {to: 'User-Email', from: 'actor.user_email'},
                {to: 'User-FullName', from: 'actor.full_name'},
                {to: 'User-VendorID', from: 'actor.vendor_id'},
                {to: 'Vendor-Name', from: 'vendor.name'},
                {to: 'Vendor-Service', from: 'vendor.service'},
            ],
        filter: function(filter_key, filter_value){
            return function(obj) {
                return !filter_key || !filter_value || dq(obj, filter_key) === filter_value;
            };
        }
    },
};

function mapObjFunction(mapFields, filter) {
    var transformSingleObj= function(obj) {
        var res = {};
        mapFields.forEach(function(f) {
           res[f.to] = dq(obj, f.from);
        });
        if (filter && !filter(res)) {
            return undefined;
        }
        return res;
    };
    return function(obj) {
        if (obj instanceof Array) {
            var res = [];
            for (var j=0; j < obj.length; j++) {
                var current = transformSingleObj(obj[j]);
                if (current) {
                    res.push(current);
                }
            }
            return res;
        }
        return transformSingleObj(obj);
    };
}

function createContext(data) {
    var createContextSingle = function(obj) {
        var res = {};
        var keys = Object.keys(obj);
        keys.forEach(function(k) {
            var values = k.split('-');
            var current = res;
            for (var j = 0; j<values.length - 1; j++) {
                if (!current[values[j]]) {
                    current[values[j]] = {};
                }
                current = current[values[j]];
            }
            current[values[j]] = obj[k];
        });
        return res;
    };
    if (data instanceof Array) {
        var res = [];
        for (var j=0; j < data.length; j++) {
            res.push(createContextSingle(data[j]));
        }
        return res;
    }
    return createContextSingle(data);
}

function sendRequest(commandData) {
    var res = http(
        base + replaceInTemplatesAndRemove(commandData.url, args) + (commandData.method === 'GET' ? encodeToURLQuery(args || commandData.defaultArgs) : ''),
        {
            Method: commandData.method,
            Headers: {
                'Authorization': ['Bearer ' + params.token],
                'Content-Type': ['application/json'],
            },
            Body: commandData.method !== 'GET' ? JSON.stringify(args || commandData.defaultArgs) : undefined
        },
        params.insecure,
        params.proxy
    );
    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        throw 'Failed to ' + commandData.url + ' , request status code: ' + res.StatusCode + ' and Body: ' + res.Body + '.';
    }
    return JSON.parse(res.Body);
}

var commandData = commands[command];
var email = args.email && command === 'cloudlock-get-user-apps' ? args.email : undefined;
var filterKey = args['filter_key'];
var filterValue = args['filter_value'];
delete args['filter_key'];
delete args['filter_value'];


var result = sendRequest(commandData);
if (command === 'test-module') {
    return 'ok';
}
var entry = {
    Type: entryTypes.note,
    Contents: result,
    ContentsFormat: formats.json,
};
if (commandData.extended) {
    var filterFunc = commandData.filter ? commandData.filter(filterKey, filterValue) : null;
    var translated = mapObjFunction(commandData.translator, filterFunc) (
      commandData.innerPath ? dq(result, commandData.innerPath) : result
    );
    entry.ReadableContentsFormat = formats.markdown;
    entry.HumanReadable = tableToMarkdown(commandData.title,translated);
    entry.EntryContext = {};
    var context = createContext(translated);
    context.Email = email;
    entry.EntryContext[commandData.contextPath] = context;
}
return entry;
