baseUrl = params.server.replace(/[\/]+$/, '') + ':' + params.port + '/';
commandDictionary = {
    'test-module': {
        url: 'topology/nodes.json',
        method: 'GET',
    },
    'verodin-get-topology-nodes': {
        url: 'topology/nodes.json',
        method: 'GET',
        extended: true,
        translator: [
            {
                contextPath: 'Verodin.Nodes(val.ID==obj.ID)',
                title: 'Verodin nodes',
                data: [
                    {to: 'ID', from: 'id'},
                    {to: 'CommMode', from: 'comm_mode'},
                    {to: 'CodeType', from: 'code_type'},
                    {to: 'Description', from: 'desc'},
                    {to: 'Gateway', from: 'gateway'},
                    {to: 'Hostname', from: 'hostname'},
                    {to: 'LastComms', from: 'last_comms'},
                    {to: 'LastUpdate', from: 'last_update'},
                    {to: 'Location', from: 'location'},
                    {to: 'Tags', from: 'user_tags'},
                    {to: 'MmgmtIp', from: 'mgmt_ip'},
                    {to: 'Name', from: 'name'},
                    {to: 'SecurityZoneID', from: 'security_zone_id'},
                    {to: 'Version', from: 'node_version'},
                    {to: 'NewMask', from: 'netmask'},
                    {to: 'OrganizationID', from: 'organization_id'},
                    {to: 'OS-type', from: 'os_base'},
                    {to: 'OS-Architecture', from: 'os_architecture'},
                    {to: 'OS-Full', from: 'os_full'},
                    {to: 'Processor', from: 'processor'},
                ]
            }
        ],
    },
    'verodin-get-topology-map': {
        url: 'topology/map.json',
        method: 'GET',
        extended: true,
        translator: [
            {
                contextPath: 'Verodin.Topolody.Device(val.ID==obj.ID)',
                title: 'Verodin devices interfaces',
                innerPath: 'device_interfaces',
                countingDict: true,
                data: [
                    {to: 'ID', from: 'id'},
                    {to: 'Updated', from: 'updated_at'},
                    {to: 'OrganizationID', from: 'organization_id'},
                    {to: 'NetworkDeviceID', from: 'network_device_id'},
                    {to: 'IP', from: 'ip'},
                ]
            },
            {
                contextPath: 'Verodin.Topolody.Nodes(val.ID==obj.ID)',
                title: 'Verodin nodes',
                innerPath: 'nodes',
                countingDict: true,
                data: [
                    {to: 'MgmtIP', from: 'mgmt_ip'},
                    {to: 'Name', from: 'name'},
                    {to: 'OS', from: 'os'},
                ]
            },
            {
                contextPath: 'Verodin.Topolody.Node.Edges',
                title: 'Verodin node edges',
                innerPath: 'node_edges',
                countingDict: true,
                data: [
                    {to: 'From', from: 'from'},
                    {to: 'To', from: 'to'},
                    {to: 'Type', from: 'type'},
                ]
            },
            {
                contextPath: 'Verodin.Topolody.Zone.Devices.Edges',
                title: 'Verodin edges',
                innerPath: 'device_zone_edges',
                countingDict: true,
                data: [
                    {to: 'From', from: 'from'},
                    {to: 'To', from: 'to'},
                    {to: 'Type', from: 'type'},
                    {to: 'Through', from: 'through'},
                ]
            },
            {
                contextPath: 'Verodin.Topolody.Zone.Devices.Interfaces.Edges',
                title: 'Verodin edges',
                innerPath: 'device_zone_edges',
                countingDict: true,
                data: [
                    {to: 'From', from: 'from'},
                    {to: 'To', from: 'to'},
                    {to: 'Type', from: 'type'},
                    {to: 'Through', from: 'through'},
                ]
            },
            {
                contextPath: 'Verodin.Topolody.Zones',
                title: 'Verodin zones',
                innerPath: 'zones',
                countingDict: true,
                data: [
                    {to: 'Description', from: 'desc'},
                    {to: 'Name', from: 'name'},
                ]
            },
        ],
    },
    'verodin-manage-sims-actions': {
        url: 'manage_sims/actions.json',
        method: 'GET',
        extended: true,
        translator: [
            {
                contextPath: 'Verodin.Simulations.Actions(val.ID==obj.ID)',
                title: 'Verodin nodes',
                data: [
                    {to: 'ID', from: 'id'},
                    {to: 'Type', from: 'action_type'},
                    {to: 'Created', from: 'created_at'},
                    {to: 'Disabled', from: 'disabled'},
                    {to: 'Name', from: 'name'},
                    {to: 'OrganizationID', from: 'organization_id'},
                    {to: 'RequireEndpoint', from: 'require_endpoint'},
                    {to: 'Updated', from: 'updated_at'},
                    {to: 'Tags-User', from: 'user_tags'},
                    {to: 'Tags-Verodin', from: 'verodin_tags'},
                    {to: 'Vid', from: 'vid'},
                ]
            }
        ],
    },
    'verodin-manage-sims-actions-run': {
        url: 'manage_sims/actions/%id%/run.json',
        method: 'POST',
        defaultArgs: {
            'schedule_run_now_selector': 'run_now',
            'repeat_job_period_type': 'minutes',
            'repeat_job_times_selector_1': 'number',
            'repeat_job_times_selector': 'number',
            'repeat_job_count': "",
            'job_name': "",
            'repeat_job_period_number_1': "",
            'repeat_job_count_1': "",
            'attack_zone_id_1': "",
            'schedule_job_datetime': "",
            'target_zone_id_1': "",
            'repeat_job_period_number': "",
           'repeat_job_period_type_1': "",
        },
        extended: true,
        translator: [
            {
                contextPath: 'Verodin.Jobs(val.ID==obj.ID)',
                title: 'Verodin run simulation - result job',
                data: [
                    {to: 'ID', from: 'id'},
                    {to: 'Description', from: 'desc'},
                    {to: 'Created', from: 'created_at'},
                    {to: 'Name', from: 'name'},
                    {to: 'OrganizationID', from: 'organization_id'},
                    {to: 'Updated', from: 'updated_at'},
                    {to: 'NodeActionQueueID', from: 'node_action_queue_id'},
                    {to: 'PlanID', from: 'plan_id'},
                    {to: 'Progress', from: 'progress'},
                    {to: 'SimulationID', from: 'simulation_id'},
                    {to: 'Status', from: 'status'},
                    {to: 'UserID', from: 'user_id'},
                ]
            }
        ],
    },
    'verodin-get-security-zones': {
        url: 'security_zones.json',
        method: 'GET',
        extended: true,
        translator: [
            {
                contextPath: 'Verodin.Zones(val.ID==obj.ID)',
                title: 'Verodin zones',
                data: [
                    {to: 'ID', from: 'id'},
                    {to: 'Description', from: 'desc'},
                    {to: 'Created', from: 'created_at'},
                    {to: 'Disabled', from: 'disabled'},
                    {to: 'Name', from: 'name'},
                    {to: 'OrganizationID', from: 'organization_id'},
                    {to: 'Updated', from: 'updated_at'},
                ]
            }
        ],
    },
    'verodin-get-security-zone': {
        url: 'security_zones/%id%.json',
        method: 'GET',
        extended: true,
        translator: [
            {
                contextPath: 'Verodin.Zones(val.ID==obj.ID)',
                title: 'Verodin zones',
                data: [
                    {to: 'ID', from: 'id'},
                    {to: 'Description', from: 'desc'},
                    {to: 'Created', from: 'created_at'},
                    {to: 'Disabled', from: 'disabled'},
                    {to: 'Name', from: 'name'},
                    {to: 'OrganizationID', from: 'organization_id'},
                    {to: 'Updated', from: 'updated_at'},
                ]
            }
        ],
    },
    'verodin-delete-security-zone': {
        url: 'security_zones/%id%',
        method: 'DELETE',
    },
    'verodin-get-sims-of-type': {
        url: 'simulations.json',
        method: 'GET',
        extended: true,
        translator: [
            {
                contextPath: 'Verodin.Simulations(val.ID==obj.ID)',
                title: 'Verodin nodes',
                data: [
                    {to: 'ID', from: 'id'},
                    {to: 'Type', from: 'simulation_type'},
                    {to: 'Created', from: 'created_at'},
                    {to: 'Disabled', from: 'disabled'},
                    {to: 'Name', from: 'name'},
                    {to: 'OrganizationID', from: 'organization_id'},
                    {to: 'StopOnError', from: 'stop_on_error'},
                    {to: 'Updated', from: 'updated_at'},
                    {to: 'Actions', from: 'sim_actions=val.split(",")'},
                    {to: 'Tags-User', from: 'user_tags'},
                    {to: 'Tags-Verodin', from: 'verodin_tags'},
                    {to: 'Vid', from: 'vid'},
                ]
            }
        ],
    },
    'verodin-get-sim': {
        url: 'simulations/%id%.json',
        method: 'GET',
        extended: true,
        translator: [
            {
                contextPath: 'Verodin.Simulations(val.ID==obj.ID)',
                title: 'Verodin nodes',
                data: [
                    {to: 'ID', from: 'id'},
                    {to: 'Type', from: 'simulation_type'},
                    {to: 'Created', from: 'created_at'},
                    {to: 'Disabled', from: 'disabled'},
                    {to: 'Name', from: 'name'},
                    {to: 'OrganizationID', from: 'organization_id'},
                    {to: 'StopOnError', from: 'stop_on_error'},
                    {to: 'Updated', from: 'updated_at'},
                    {to: 'Actions', from: 'sim_actions=val.split(",")'},
                    {to: 'Tags-User', from: 'user_tags'},
                    {to: 'Tags-Verodin', from: 'verodin_tags'},
                    {to: 'Vid', from: 'vid'},
                    {to: 'Step-Name', from: 'steps.name'},
                    {to: 'Step-Order', from: 'steps.order'},
                    {to: 'Step-Created', from: 'steps.created_at'},
                    {to: 'Step-Updated', from: 'steps.updated_at'},
                    {to: 'Step-Action-IDs', from: 'steps.sim_actions.id'},
                ]
            }
        ],
    },
    'verodin-delete-sim': {
        url: 'simulations/%id%',
        method: 'DELETE',
    },
    'verodin-get-jobs': {
        url: 'jobs.json',
        method: 'GET',
        extended: true,
        translator: [
            {
                contextPath: 'Verodin.Jobs(val.ID==obj.ID)',
                title: 'Verodin nodes',
                data: [
                    {to: 'ID', from: 'id'},
                    {to: 'Description', from: 'desc'},
                    {to: 'Created', from: 'created_at'},
                    {to: 'Name', from: 'name'},
                    {to: 'OrganizationID', from: 'organization_id'},
                    {to: 'Updated', from: 'updated_at'},
                    {to: 'NodeActionQueueID', from: 'node_action_queue_id'},
                    {to: 'PlanID', from: 'plan_id'},
                    {to: 'Progress', from: 'steps.name'},
                    {to: 'Step-Order', from: 'progress'},
                    {to: 'SimulationID', from: 'simulation_id'},
                    {to: 'Status', from: 'status'},
                    {to: 'UserID', from: 'user_id'},
                ]
            }
        ],
    },
    'verodin-get-job': {
        url: 'jobs/%id%.json',
        method: 'GET',
        extended: true,
        translator: [
            {
                contextPath: 'Verodin.Jobs(val.ID==obj.ID)',
                title: 'Verodin nodes',
                data: [
                    {to: 'ID', from: 'id'},
                    {to: 'Description', from: 'desc'},
                    {to: 'Created', from: 'created_at'},
                    {to: 'Name', from: 'name'},
                    {to: 'OrganizationID', from: 'organization_id'},
                    {to: 'Updated', from: 'updated_at'},
                    {to: 'NodeActionQueueID', from: 'node_action_queue_id'},
                    {to: 'PlanID', from: 'plan_id'},
                    {to: 'Progress', from: 'progress'},
                    {to: 'SimulationID', from: 'simulation_id'},
                    {to: 'Status', from: 'status'},
                    {to: 'UserID', from: 'user_id'},
                ]
            }
        ],
    },
    'verodin-run-job-again': {
        url: 'jobs/%id%/run_again',
        method: 'GET',
    },
    'verodin-get-job-sim-actions': {
        url: 'jobs/%id%/sim_actions.json',
        method: 'GET',
        extended: true,
        translator: [
            {
                contextPath: 'Verodin.Jobs(val.ID==obj.ID)',
                title: 'Verodin nodes',
                data: [
                    {to: 'Actions-Label', from: 'label'},
                    {to: 'Actions-Value', from: 'value'},
                ]
            }
        ],
    },
    'verodin-job-cancel': {
        url: 'jobs/%id%/cancel',
        method: 'GET',
    },
};

function createContext(data, id) {
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
        if (!res.ID && id) {
            res.ID = id;
        }
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


var sendRequest = function(url, method, args) {
    var httpParams = {
       Method: method,
       Headers: {
            'Content-Type': ['application/json']
       },
       Username: params.credentials.identifier,
       Password: params.credentials.password,
       Body: method !== 'GET' ? JSON.stringify(args) : undefined
    };
    var res = http(
            baseUrl + url + (method === 'GET' && method ? encodeToURLQuery(args) : ''),
            httpParams,
            params.insecure,
            params.proxy,
            false
        );

    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        throw 'Request ' + url + ' failed, request status code: ' + res.StatusCode + ' and Body: ' + res.Body + '.';
    }
    if (!res.Body) {
        return 'Done';
    }
    try {
        return JSON.parse(res.Body);
    }
    catch (ex) {
        throw 'Failed to create JSON from response ' + res.Body + ', exception is ' + ex;
    }
}

var toArray = function(obj) {
    res = [];
    keys = Object.keys(obj);
    for (var k in keys) {
        res.push(obj[keys[k]]);
    }
    return res;
}

var createIncidentFromJob = function(incident) {
    var keys = Object.keys(incident);
    var labels = [];
    for (var i = 0; i<keys.length; i++) {
        labels.push({'type': keys[i], 'value': String(incident[keys[i]])});
    }
    return {
        "name": incident.id + ' ' + incident.desc,
        "labels": labels,
        "rawJSON": JSON.stringify(incident),
    }
}

if (command === 'fetch-incidents') {
    var lastRun = getLastRun();
    var lastID = lastRun && lastRun.startID ? lastRun.startID : 0;
    var startID = lastID;
    currentCommand = commandDictionary['verodin-get-jobs'];
    var res = sendRequest(replaceInTemplatesAndRemove(currentCommand.url, args), currentCommand.method, args);
    var incidents = [];
    for (var i = 0; i < res.length; i++) {
        if (res[i].id > lastID) {
            startID = Math.max(startID, res[i].id);
            incidents.push(createIncidentFromJob(res[i]));
        }
    }
    setLastRun({startID: startID});
    return JSON.stringify(incidents);
}

var id = args.id;
currentCommand = commandDictionary[command];
if (currentCommand.defaultArgs) {
    keys = Object.keys(currentCommand.defaultArgs);
    for (var k in keys) {
        if (!args[keys[k]]) {
            args[keys[k]] = currentCommand.defaultArgs[keys[k]];
        }
    }
}
var result = sendRequest(replaceInTemplatesAndRemove(currentCommand.url, args), currentCommand.method, args);
if (command === 'test-module') {
    return 'ok';
}
var entries = [];
if (currentCommand.extended) {
    for (var j in currentCommand.translator) {
        var current = currentCommand.translator[j];
        var entry = {
            Type: entryTypes.note,
            Contents: result,
            ContentsFormat: formats.json,
        };
        var currentContent = current.innerPath ? dq(result, current.innerPath) : result;
        var translated = mapObjFunction(current.data) (current.countingDict ? toArray(currentContent) : currentContent);
        entry.ReadableContentsFormat = formats.markdown;
        entry.HumanReadable = tableToMarkdown(current.title,translated);
        entry.EntryContext = {};
        var context = createContext(translated, id);
        entry.EntryContext[current.contextPath] = context;
        entries.push(entry);
    }
} else {
    return result;
}
return entries;
