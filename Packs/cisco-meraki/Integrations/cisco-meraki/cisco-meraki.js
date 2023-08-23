    /**
       * flatten nested object to top level fields
       * @param {Object | Array<Object>} ob - object to flatten
       * @returns {String} the flatten object
       * { "a": "bla", "b": { "c": "hello", "d": "there" } } => { "a": "bla", "b.c" = "hello", "b.d": "there" }
    */

    var flattenObject = function(ob) {
        var toReturn = {};

        for (var i in ob) {
            if (!ob.hasOwnProperty(i)) continue;

            if ((typeof ob[i]) == 'object') {
                var flatObject = flattenObject(ob[i]);
                for (var x in flatObject) {
                    if (!flatObject.hasOwnProperty(x)) continue;

                    toReturn[i + '.' + x] = flatObject[x];
                }
            } else {
                toReturn[i] = ob[i];
            }
        }
        return toReturn;
    };


    /**
       * Converts a demisto table in JSON form to a Markdown table
       * @param {String} name - the name of the table
       * @param {Object | Array<Object>} table - the JSON table - Array of objects with the same keys
       * @param {Array} headers - optinal, the output markdown table will show only this headers (by order)
       * @returns {String} Markdown representation of the original list
    */

    var tableToMd = function(name, table, headers) {

        if (!(table instanceof Array)){
              table = [table];
          }

        var res = '### ' + name + '\n';
        table = table.map(flattenObject);
        if(table && table.length) {
            // use table's keys if headers are not provieded
            if(!headers) {
                headers = Object.keys(table[0]);
            }

            // headers
            res += headers.join('|') + '\n';
            res += headers.map(function(h) { return '-'; }).join('|') + '\n';

            // body
            for(var i = 0; i< table.length; i++) {
                var obj = table[i];
                var values = [];
                var val;
                headers.forEach(function(key) {
                    val = '-';
                    if (obj[key] || obj[key] === '0' || obj[key] === '0') {
                        val = obj[key];
                    }
                    values.push(val);
                });
                res += values.join('|') + '\n';
            }
        } else {
            res += '**No entries.**\n';
        }
        return res;
    }


    var createTableEntry = function (name, contents, context, headers) {
        return {
            // type
            Type: entryTypes.note,
             // contents
            ContentsFormat: formats.json, Contents: contents,
            // human-readable
            ReadableContentsFormat: formats.markdown, HumanReadable: tableToMd(name, contents, headers),
            // context
            EntryContext: context
        };
    }


    var createTextEntry = function(text) {
        return text;
    }


    var createMapEntry = function(obj) {

        var location = {
            lat: obj.lat,
            lng: obj.lng
        };

        return {
            // type
            Type: 15, // entryTypes.map,
             // contents
            ContentsFormat: formats.json, Contents: location
        };
    }


    var merakiUrlPrefix = 'https://api.meraki.com/api/v0/';

    var apiKey = params.apikey_creds ? params.apikey_creds.password : params.apiKey;

    var insecure = params.insecure;

    var proxy = params.proxy;


    var sendRequest = function(url, method, body) {

        var requestMethod = method || 'GET';
        var requestUrl = merakiUrlPrefix + url;

        var httpParams = {
            Method: requestMethod,
            Headers: {
                'X-Cisco-Meraki-API-Key': [apiKey],
                'Content-Type': ['application/json'],
            },
            Body: body
        };

        var res = http(
            requestUrl,
            httpParams,
            insecure,
            proxy,
            true // no redirect (e.i. request is not automatically redirect - instead it will return 302)
        );

        // catch redirect response
        if (res && (res.StatusCode === 302 || res.StatusCode === 308)) {
            var redirectUrl = res.Headers.Location;

            res = http(
                    redirectUrl,
                    httpParams,
                    insecure,
                    proxy
            );
        }

        if (!res || res.StatusCode < 200 || res.StatusCode >= 300) {
            throw 'Request Failed. '
            + '\nUrl: ' + requestUrl
            + '\nStatus code: ' + res.StatusCode
            + '\nSurl: ' + res.StatusCode
            + '.\nBody: ' + JSON.stringify(res) + '.';
        }

        if(requestMethod === 'POST') {
            // action succeed - than just return true
            return true;
        } else {
             var resBody = JSON.parse(res.Body);
        if (resBody === undefined) {
           throw 'Request Failed, returned response with no body';
        }
        return resBody;
        }
    };


    /**
       * return a function that transform object from some structure to other
       * @param {Array} fields - array of {from: String, to: String} - to transform by
       * @returns {Function} array from the original string-list
    */

    var mapObjFunction = function(mapFields) {
        return function(obj) {
            var res = {};
            mapFields.forEach(function(f) {
               res[f.to] = (obj[f.from] !== undefined) ? obj[f.from] : null;
            });
            return res;
        }
    }


    // maps device api-object to context-object

    var mapDeviceFunction = mapObjFunction([
        { from: 'serial', to: 'Serial' },
        { from: 'name', to: 'Name' },
        { from: 'mac', to: 'MAC' },
        { from: 'lat', to: 'Lat' },
        { from: 'lng', to: 'Lng' },
        { from: 'address', to: 'Address' },
        { from: 'lanIp', to: 'LanIp' },
        { from: 'tags', to: 'Tags' },
        { from: 'networkId', to: 'NetworkId' },
        { from: 'model', to: 'Model' },
        { from: 'claimedAt', to: 'ClaimedAt' },
        { from: 'publicIp', to: 'PublicIp' }
    ]);


    // maps firewall api-object to context-object

    var mapFirewallFunction = mapObjFunction([
        { from: 'comment', to: 'Comment' },
        { from: 'policy', to: 'Policy' },
        { from: 'protocol', to: 'Protocol' },
        { from: 'destPort', to: 'DestPort' },
        { from: 'destCidr', to: 'DestCidr' }
    ]);


    // --------- organizations ------- //

    var fetchOrganizations = function() {
        // get result from http
        var organizations = sendRequest('organizations');

        // create context
        var context = {};
        if(organizations && organizations.length) {
            context.Organization = organizations.map(mapObjFunction([
                { from: 'id', to: 'ID' },
                { from: 'name', to: 'Name' }
            ]));
        }
        return createTableEntry("Organizations", organizations, context);
    };


    var getOrganizationLiceseState = function(organizationId, headers) {
        // get result from http
        var license = sendRequest('organizations/' + organizationId + '/licenseState');

        return createTableEntry("Organization License State", license, {}, headers);
    };


    var fetchOrganizationInventory = function(organizationId, headers) {
        // get result from http
        var devices = sendRequest('organizations/' + organizationId + '/inventory');

         // create context
        var context = {};
        if(devices && devices.length) {
            context.Device = devices.map(mapDeviceFunction);
        }

        return createTableEntry("Organization Inventory", devices, context, headers);
    };


    // --------- networks ------- //


    var fetchNetworks = function(organizationId, headers) {
         // get result from http
        var networks = sendRequest('organizations/' + organizationId + '/networks');

         // create context
        var context = {};
        if(networks && networks.length) {
            context.Network = networks.map(mapObjFunction([
                { from: 'id', to: 'ID' },
                { from: 'organizationId', to: 'OrganizationId' },
                { from: 'type', to: 'Type' },
                { from: 'name', to: 'Name' },
                { from: 'timeZone', to: 'Timezone' },
                { from: 'tags', to: 'Tags' },
            ]));
        }

        return createTableEntry("Networks", networks, context, headers);
    };


    // --------- devices ------- //


    var fetchDevices = function(networkId, headers) {
         // get result from http
        var devices = sendRequest('networks/' + networkId + '/devices');

         // create context
        var context = {};
        if(devices && devices.length) {
            context.Device = devices.map(mapDeviceFunction);
        }

        return createTableEntry("Devices", devices, context, headers);
    };


    var fetchDeviceUplink = function(networkId, serial, headers) {
        // get result from http
        var uplinks = sendRequest('networks/' + networkId + '/devices/' + serial + '/uplink');

         // create context
        var context = {};
        if(uplinks && uplinks.length) {
            context.Uplink = uplinks.map(mapObjFunction([
                { from: 'status', to: 'Status' },
                { from: 'interface', to: 'Interface' }
            ]));
        }
        return createTableEntry("Device Uplink", uplinks, context, headers);
    };


    var fetchDeviceClients = function(serial, timespan, headers) {
        // get result from http
        var clients = sendRequest('devices/' + serial + '/clients?timespan=' + timespan);

         // create context
        var context = {};
        if(clients && clients.length) {
            context.Client = clients.map(mapObjFunction([
                { from: 'description', to: 'Description' },
                { from: 'mdnsName', to: 'mDNSName' },
                { from: 'dhcpHostname', to: 'Hostname' },
                { from: 'usage', to: 'Usage' },
                { from: 'mac', to: 'MAC' },
                { from: 'ip', to: 'IP' },
                { from: 'id', to: 'ID' },
                { from: 'vlan', to: 'VLAN' }
            ]));
        }

        return createTableEntry("Clients", clients, context, headers);
    };


    var getDevice = function(networkId, serial, headers) {
         // get result from http
        var device = sendRequest('networks/' + networkId + '/devices/' + serial);

         // create context
        var context = {};
        if(device) {
            context.Device = mapDeviceFunction(device);
        }

        return [createTableEntry("Device " + serial, device, context, headers), createMapEntry(device)];
    };


    var removeDevice = function(networkId, serial) {
        var res = sendRequest('networks/' + networkId + '/devices/' + serial + '/remove', 'POST');

        var textResult;
        if(res) {
                textResult = 'Successfully removed device ' + serial + ' from network ' + networkId;
        } else {
            textResult = 'Failed to removed device ' + serial + ' from network ' + networkId;
        }
        return createTextEntry(textResult);
    };


    var updateDevice = function(networkId, serial, updateArgs) {
        //send update request
        var url = 'networks/' + networkId + '/devices/' + serial;

        var body = {};
        var keys = Object.keys(updateArgs);
        keys.forEach(function (key) {
           if(updateArgs[key]) {
               body[key] = updateArgs[key];
           }
        });

        var device = sendRequest(url, 'PUT', JSON.stringify(body));

        // create context
        var context = {};
        if(device) {
            context.Device = mapDeviceFunction(device);
        }

        return createTableEntry("Successfully Updated Device " + serial, device, context);
    }


    var claimDevice = function(networkId, serial) {
        var url = 'networks/' + networkId + '/devices/claim';
        var body = { serial: serial };

        var succeed = succeed(url, 'POST', JSON.stringify(body));

        var resStr;
        if(succeed) {
            resStr = 'Successfully joined device ' + serial + ' to network ' + networkId;
        } else {
            resStr = 'Failed to claim device ' + serial + ' to network ' + networkId;
        }
    };


    var fetchSsids = function(networkId, headers) {
        // get result from http
        var ssids = sendRequest('networks/' + networkId + '/ssids');


         // create context
        var context = {};
        if(ssids && ssids.length) {
            context.SSID = ssids
            .map(mapObjFunction([
                { from: 'name', to: 'Name' },
                { from: 'splashPage', to: 'SplashPage' },
                { from: 'bandSelection', to: 'BandSelection' },
                { from: 'enabled', to: 'Enabled' },
                { from: 'authMode', to: 'AuthMode' },
                { from: 'walledGardenRanges', to: 'WalledGardenRanges' },
                { from: 'number', to: 'Number' }
            ]))
            .map(function(ssid) {
                ssid.NetworkId = networkId;
                return ssid;
            });
        }
        return createTableEntry("SSIDs", ssids, context, headers);
    };


    var fetchFirewallRules = function(networkId, number, headers) {
        // get result from http
        var firewalls = sendRequest('networks/' + networkId + '/ssids/' + number + '/l3FirewallRules');
         // create context
        var context = {};
        if(firewalls && firewalls.length) {
            context.Firewall = firewalls
            .map(mapFirewallFunction)
            .map(function(fireWall) {
                fireWall.NetworkId = networkId;
                fireWall.Number = number;
                return fireWall;
            });
        }
        return createTableEntry("Firewall Rules", firewalls, context, headers);
    };


    var updateFirewallRules = function(networkId, number, allowLanAccess, removeOthers, rule) {
        var url = 'networks/' + networkId + '/ssids/' + number + '/l3FirewallRules';

        var rules;
        if(removeOthers) {
            rules = [rule];
        } else {
            rules = sendRequest('networks/' + networkId + '/ssids/' + number + '/l3FirewallRules');
            rules = rules.slice(0, -2); // remove defulat & local LAN access rules
            rules.push(rule);
        }
        var body = {
            allowLanAccess: allowLanAccess,
            rules: rules
        };

        var firewalls = sendRequest(url, 'PUT', JSON.stringify(body));

         // create context
        var context = {};
        if(firewalls && firewalls.length) {
            context.Firewall = firewalls
            .map(mapFirewallFunction)
            .map(function(fireWall) {
                fireWall.NetworkId = networkId;
                fireWall.Number = number;
                return fireWall;
            });
        }
        return createTableEntry("Firewall Rules", firewalls, context);
    };



    // --------------------- main -------------------- //

    switch (command) {
        case 'test-module':
            fetchOrganizations();
            return 'ok';
        // organization
        case 'meraki-fetch-organizations':
            return fetchOrganizations();
        case 'meraki-fetch-organization-inventory':
            return fetchOrganizationInventory(
                args.organizationId,
                args.headers && args.headers.split(',')
            );
        case 'meraki-get-organization-license-state':
            return getOrganizationLiceseState(
                args.organizationId,
                args.headers && args.headers.split(',')
            );
        // network
        case 'meraki-fetch-networks':
            return fetchNetworks(
                args.organizationId,
                args.headers && args.headers.split(',')
            );
        // device
        case 'meraki-fetch-devices':
            return fetchDevices(
                args.networkId,
                args.headers && args.headers.split(',')
            );
        case 'meraki-get-device':
            return getDevice(
                args.networkId,
                args.serial,
                args.headers && args.headers.split(',')
            );
        case 'meraki-update-device':
            return updateDevice(
                args.networkId,
                args.serial,
                { // updateArgs
                    name: args.name,
                    tags: args.tags,
                    address: args.address,
                    lat: args.lat,
                    lng: args.lng
                }
            );
        case 'meraki-claim-device':
            return claimDevice(
                args.serial,
                args.networkId
            );
        case 'meraki-fetch-device-uplink':
             return fetchDeviceUplink(
                args.networkId,
                args.serial,
                args.headers && args.headers.split(',')
            );
        case 'meraki-fetch-clients':
            return fetchDeviceClients(
                args.serial,
                args.timespan,
                args.headers && args.headers.split(',')
            );
        case 'meraki-fetch-firewall-rules':
            return fetchFirewallRules(
                args.networkId,
                args.number,
                args.headers && args.headers.split(',')
            );
        case 'meraki-update-firewall-rules':
            return updateFirewallRules(
                args.networkId,
                args.number,
                (args.allowLanAccess === "true"),
                (args.removeOthers === "true"),
                {
                    policy: args.policy,
                    protocol: args.protocol,
                    destPort: args.destPort,
                    destCidr: args.destCidr,
                    comment: args.comment
                }
            );
        case 'meraki-remove-device':
            var networkId = args.networkId;
            var serial = args.serial;
            return removeDevice(networkId, serial);
        // ssid
        case 'meraki-fetch-ssids':
            return fetchSsids(
                args.networkId,
                args.headers && args.headers.split(',')
            );
        default:
            throw 'Unrecognized command';
    }