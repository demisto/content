// handle '/' at the end of the url
var base_url = params.url.slice(0, params.url.length - params.url.match('/*$')[0].length) + ':' + params.port + '/Konfigurator/REST';
var session_id = '';

//body should be in xml format
function sendRequest(method, url_suffix, headers, body) {
    headers = headers || {};
    body = body || '';

    // add default headers
    if (!("Accept" in headers)) {
        headers.Accept = ['application/mwg+xml'];
    }
    if (!("Content-Type" in headers)) {
        headers['Content-Type'] = ['application/mwg+xml'];
    }
    headers.Cookie = ['JSESSIONID=' + session_id];

    var res = http(
        base_url + url_suffix,
        {
            Method: method,
            Headers: headers,
            Body: body,
        },
        params.insecure,
        params.useproxy
    );

    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        if (res.Status.indexOf('pass=') !== -1) {
            throw 'Request Failed.\nStatus code: ' + res.StatusCode + '. Check your Server URL and Port.';
        }
        throw 'Request Failed.\nStatus code: ' + res.StatusCode + '.\nBody: ' + JSON.stringify(res) + '.';
    }
    return res.Body;
}

function login() {
    var cmd_url = '/login' + encodeToURLQuery({
        'userName' : params.credentials.identifier,
        'pass' : params.credentials.password
    });
    session_id = sendRequest('POST', cmd_url);
}

function logout() {
    var cmd_url = '/logout';
    sendRequest('POST', cmd_url);
}

function list_to_demisto_entry(title, list_header, list_id) {
    var list_entries = [];

    // if no entries
    if (list_header.content) {
        // check if list has multiple entries or single entry
        if (list_header.content.listEntry instanceof Array) {
            list_entries = list_header.content.listEntry;
        } else {
            list_entries = [list_header.content.listEntry];
        }
    }

    var context_entries = [];
    for (var i = 0; i < list_entries.length; i++) {
        context_entries.push({
            ListID : list_id,
            Pos : i,
            Name : list_entries[i].entry,
            Description : list_entries[i].description
        });
        list_entries[i].ListID = list_id;
        list_entries[i].Pos = i;
    }
    var context_list = {
        ID : list_id,
        Name : list_header['-name'],
        Description : list_header.description,
        Type : list_header['-typeId'],
    };

    var context = {
        'MWG.Lists(val.ID && val.ID && val.ID == obj.ID)' : context_list,
        'MWG.ListEntries(val.Name && val.ListID && val.Name == obj.Name && val.ListID == obj.ListID)' : context_entries
    };
    var entries_md = (list_entries.length > 0) ? tableToMarkdown(title, context_entries, ['Pos', 'Name', 'Description']) : 'List is empty\n';
    return {
        Type : entryTypes.note,
        Contents : list_entries,
        ContentsFormat : formats.json,
        HumanReadable : tableToMarkdown('List Properties', [context_list]) + entries_md,
        EntryContext : context
    };
}

function list_entry_to_demisto_entry(title, list_entry, ids, update_context) {
    update_context = update_context || true;
    list_entry.ListID = ids[0];
    list_entry.Pos = ids[1];

    if (update_context) {
        return createEntry(list_entry, {
            contextPath : 'MWG.ListEntries(val.Name && val.ID && val.Name == obj.Name && val.ID == obj.ID)',
            title : title,
            data : [
                {to : 'ListID', from : 'ListID', humanReadable : false},
                {to : 'Pos', from : 'Pos'},
                {to : 'Name', from : 'entry'},
                {to : 'Description', from : 'description'},
            ],
        }, undefined, pascalToSpace);
    } else {
        return createEntry(list_entry, {
            title : title,
            data : [
                {to : 'ListID', from : 'ListID', humanReadable : false},
                {to : 'Pos', from : 'Pos', humanReadable : false},
                {to : 'Name', from : 'entry'},
                {to : 'Description', from : 'description'},
            ],
        }, undefined, pascalToSpace);
    }
}

function getListIdByName() {
    var cmd_url = '/list';
    if (args.list_name) {
        payload = {}
        payload['name'] = args.list_name
        cmd_url += encodeToURLQuery(payload);
    }

    var res = '';

    login();
    try {
        res = sendRequest('GET', cmd_url);
    }
    finally {
        logout();
    }

    res = res.split('\n');
    list_names = [];
    for (var i in res) {
        if (res[i]) {
            list_names.push({
                Index : i,
                Name : res[i],
                Display: args.list_name,
            });
        }
    }


    return list_names[0]['Name'];
}



function get_lists() {
    var cmd_url = '/list';
    if (args.name) {
        cmd_url += encodeToURLQuery(args);
    }
    var res = '';

    login();
    try {
        res = sendRequest('GET', cmd_url);
    }
    finally {
        logout();
    }

    res = res.split('\n');
    list_names = [];
    for (var i in res) {

        if (res[i]) {
            list_names.push({
                Index : i,
                Name : res[i],
                Display: args.name,
            });
        }
    }

    if (args.name) {
        data = [
            {to : 'Index', from : 'Index'},
            {to : 'Name', from : 'Name'},
            {to : 'Display', from : 'Display'}
        ];
    } else {
        data = [
            {to : 'Index', from : 'Index'},
            {to : 'Name', from : 'Name'},
        ];
    }

    return createEntry(list_names, {
        contextPath : 'MWG.Lists(val.Name && val.Name == obj.Name)',
        title : 'All available lists',
        data : data,
    });
}

function get_list(list_id, list_name) {
    if (list_name) {
        list_id = getListIdByName()
    }
    var cmd_url = '/list/' + list_id;
    var res = '';

    login();
    try {
        res = sendRequest('GET', cmd_url);
    }
    finally {
        logout();
    }

    res = JSON.parse(x2j(res));
    return list_to_demisto_entry(res.list['-name'] + ': ' + res.list.description, res.list, list_id);
}


function get_listJSON(list_id) {
    var cmd_url = '/list/' + list_id;
    var res = '';

    login();
    try {
        res = sendRequest('GET', cmd_url);
    }
    finally {
        logout();
    }

    res = JSON.parse(x2j(res));

    return res
}

function get_list_entry(list_id, list_name, entry_pos) {
    if (list_name) {
        list_id = getListIdByName()
    }
    var cmd_url = '/list/' + list_id + '/entry/' + entry_pos;
    var res = '';

    login();
    try {
        res = sendRequest('GET', cmd_url);
    }
    finally {
        logout();
    }

    res = JSON.parse(x2j(res));
    return list_entry_to_demisto_entry('entry #' + entry_pos, res.listEntry, [list_id, entry_pos]);
}

function insert_entry(list_id, list_name, entry_pos, name, description) {
    if (list_name) {
        list_id = getListIdByName()
        var getpos = get_listJSON(list_id)['list']['content']['listEntry']

        if (!Array.isArray(getpos)){
            getpos = [getpos]
        }

        for (i=0; i < getpos.length; i++)
        {

            if (name === getpos[i]['entry']) {
                entry_pos = i.toString()
                if (entry_pos){
                    return 'Entry already exist in the given list >>>> ' + list_name
                }
            }

        }


        if (!getpos){
            entry_pos= "0"
        }
        else {
            log(JSON.stringify(getpos))
            entry_pos = getpos.length.toString()
        }

    }
    var cmd_url = '/list/' + list_id + '/entry/' + entry_pos + '/insert';
    var query = '<listEntry><entry>' + escapeXMLChars(name) + '</entry><description>' + escapeXMLChars(description || '') + '</description></listEntry>';
    var res = '';

    login();
    try {
        res = sendRequest('POST', cmd_url, {}, query);
        sendRequest('POST', '/commit');
    }
    finally {
        logout();
    }

    res = JSON.parse(x2j(res));
    return list_entry_to_demisto_entry('entry #' + entry_pos, res.listEntry, [list_id, entry_pos]);
}

function delete_entry(list_id, list_name, entry_pos, value) {
    if (list_name) {
        list_id = getListIdByName()
        var wholelist = get_listJSON(list_id)['list']['content']['listEntry']

        if (!Array.isArray(wholelist)){
            wholelist = [wholelist]
        }

        for (i=0; i < wholelist.length; i++)
        {

            if (value === wholelist[i]['entry']) {
                entry_pos = i.toString()
            }

        }

        if (!entry_pos){
            return 'Unable to find pos for the given value >>>> ' + value
        }

    }
    var cmd_url = '/list/' + list_id + '/entry/' + entry_pos;
    var res = '';

    login();
    try {
        res = sendRequest('DELETE', cmd_url);
        sendRequest('POST', '/commit');
    }
    finally {
        logout();
    }

    res = JSON.parse(x2j(res));
    return list_entry_to_demisto_entry('Deleting entry #' + entry_pos, res.listEntry, [list_id, entry_pos], false);
}

// The command input arg holds the command sent from the user.
switch (command) {
    case 'mwg-get-available-lists':
        return get_lists();
    case 'mwg-get-list':
        return get_list(args.list_id, args.list_name);
    case 'mwg-get-list-entry':
        return get_list_entry(args.list_id, args.list_name, args.entry_pos);
    case 'mwg-insert-entry':
        return insert_entry(args.list_id, args.list_name, args.entry_pos, args.name, args.description, args.list_name);
    case 'mwg-delete-entry':
        return delete_entry(args.list_id, args.list_name, args.entry_pos, args.value);

    // This is the call made when pressing the integration test button.
    case 'test-module':
        login();
        logout();
        return 'ok';
}
