var toCamelCase = function(string){
    var str = ' '+string.trim();
    str=str.replace(/ ([a-z,A-Z])/g, function (g) { return g[1].toUpperCase(); });
    return str;
};

var sendRequest = function(url) {
    var res = http(
        url,
        {
            Method: 'GET',
            Headers: {
                Accept: ['application/json']
            }
        },
        params.insecure,
        params.proxy
    );
    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        throw 'Request Failed.\nStatus code: ' + res.StatusCode + '.\nBody: ' + JSON.stringify(res) + '.';
    }

    try {
        return JSON.parse(res.Body);
    }
    catch (err) {
        throw 'Failed to parse JSON';
    }
};

var addKeyToJson = function(cur, toAdd){
    if(!cur){
        return toAdd;
    }
    if(!Array.isArray(cur)){
        return [cur, toAdd];
    }
    cur.push(toAdd);
    return cur;
};

var changeKeys = function(conv, obj){
    var output = {};
    for (var i in obj) {
        if (Object.prototype.toString.apply(obj[i]) === '[object Object]') {
            output[conv(i)] = changeKeys(conv, obj[i]);
        } else {
            output[conv(i)] = obj[i];
        }
    }
    return output;
};

var callWhoIs = function(url, query, parsed){
    var whois_endpoint = `${url}/v1/${query}/whois/parsed/${encodeToURLQuery(DOMAINTOOLS_PARAMS)}`
    var res = sendRequest(whois_endpoint)

    var error = res.response.error;
    if(error && error.code === 206){
        parsed = false;
        log('error code 206');
    }
    var splitRes = res.response.whois.record.split('\n');
    var md = '### DomainTools whois result for '+ query + '\n';
    var resMap = {};
    splitRes.forEach(function(entry){
        splitEntry = entry.split(/:\s(.+)/);
        if(splitEntry[1]){
            splitEntry[0] = toCamelCase(splitEntry[0]);
            md += '**'+splitEntry[0]+':** '+splitEntry[1]+'\n';
            resMap[splitEntry[0]] = addKeyToJson(resMap[splitEntry[0]], splitEntry[1]);
        }
    });

    var context;
    if(parsed === 'false'){
        context = {'Domain': {'Name': res.response.record_source, 'Whois': resMap}};
    }else{
        context = {'Domain': {'Name': res.response.record_source, 'Whois': changeKeys(toCamelCase, res.response.parsed_whois)}};
    }

    return {
            Type: entryTypes.note,
            Contents: res,
            ContentsFormat: formats.json,
            ReadableContentsFormat: formats.markdown,
            HumanReadable: md,
            EntryContext: context
        };
};

var scoreConv = function(score, threshold){
    if(threshold){
        return score>=threshold ? 3 : 1;
    }
    if(score === 0)
        return 1;
    if(score > 0 && score <=69)
        return 2;
    if(score >= 70)
        return 3;
    return -1;
};

var callDomain = function(url, domain, threshold){
    var api_params = Object.assign(DOMAINTOOLS_PARAMS, {"domain": domain})
    var domain_reputation_endpoint = `${url}/v1/reputation/${encodeToURLQuery(api_params)}`
    var repRes = sendRequest(domain_reputation_endpoint)
    var md = 'Domain '+repRes.response.domain+' found with risk score of '+ repRes.response.risk_score +'.';
    var context = {
        'DBotScore' : {
            'Indicator' : domain,
            'Score' : scoreConv(repRes.response.risk_score, threshold),
            'Type': 'domain',
            'Vendor': 'domaintools',
            'Reliability': params.integrationReliability
        }
    };
    if(context.DBotScore.Score === 3){
        addMalicious(context, outputPaths.domain, {'Name' : domain, 'RiskScore': repRes.response.risk_score ,'Malicious' : {'Vendor' : 'DomainTools'}});
    }

    return {
            Type: entryTypes.note,
            Contents: repRes,
            ContentsFormat: formats.json,
            HumanReadable: md,
            ReadableContentsFormat: formats.markdown,
            EntryContext: context
        };
};

var callProfile= function(url, domain){
    var domain_profile_endpoint = `${url}/v1/${domain}/${encodeToURLQuery(DOMAINTOOLS_PARAMS)}`
    var domRes = sendRequest(domain_profile_endpoint)
    return {
            Type: entryTypes.note,
            Contents: domRes,
            ContentsFormat: formats.json
        };
};

var argToUrlParam = function(string){
    var map = {
        'exclude':'exclude_query',
        'maxLength':'max_length',
        'minLength':'min_length',
        'hesHyphen':'has_hyphen',
        'hasNumber':'has_number',
        'activeOnly':'active_only',
        'deletedOnly':'deleted_only',
        'anchorLeft':'anchor_left',
        'anchorRight':'anchor_right',
        'pageNumber':'page'
    };
    return map[string] ? map[string] : string;
};

var callDomainSearch = function(url, args){
    args = changeKeys(argToUrlParam,args);
    args.api_username = params.username;
    args.api_key = params.key;

    var api_params = Object.assign(DOMAINTOOLS_PARAMS, args)
    var res = sendRequest(`${url}/v2/domain-search/${encodeToURLQuery(api_params)}`);
    var results = res.response.results;

    var md = '';
    var numDomains = 0;
    var context = {'Domain' : []};
    if(results && results.length > 0){
        results.forEach(function(result){
            if(result.hashad_tlds && result.hashad_tlds.length > 0){
                result.hashad_tlds.forEach(function(tld){
                    md+='* '+result.sld+'.'+tld+'\n';
                    numDomains++;
                    context.Domain.push({'Name' : result.sld+'.'+tld});
                });
            }
        });
    }

    return {
            Type: entryTypes.note,
            Contents: res,
            ContentsFormat: formats.json,
            ReadableContentsFormat: formats.markdown,
            HumanReadable: 'Found '+numDomains +' domains:\n'+md,
            EntryContext: context
        };
};

var callReverseIP = function(url, args){
    var md = '';
    var context = {'Domain' : []};
    var res;
    var addresses;

    var api_params = Object.assign(DOMAINTOOLS_PARAMS, {"limit": args.limit? args.limit : 50})
    if(args.domain){
        var reverse_ip_endpoint = `${url}/v1/${args.domain}/reverse-ip/${encodeToURLQuery(api_params)}`
        res = sendRequest(reverse_ip_endpoint)
    }
    else if(args.ip){
        var host_domains_endpoint = `${url}/v1/${args.ip}/host-domains/${encodeToURLQuery(api_params)}`
        res = sendRequest(host_domains_endpoint)
    }
    addresses = res.response.ip_addresses;
    if(!Array.isArray(addresses)){
        addresses = [addresses];
    }

    addresses.forEach(function(address){
        md+= '\nFound ' + address.domain_count + ' domains for ' +address.ip_address + '\n';
        address.domain_names.forEach(function(domain){
            md += '* ' + domain + '\n';
            context.Domain.push({'Name': domain, 'DNS' : {'Address' : address.ip_address}});
        });
    });

    return {
        Type: entryTypes.note,
        Contents: res,
        ContentsFormat: formats.json,
        ReadableContentsFormat: formats.markdown,
        HumanReadable: md,
        EntryContext: context
    };
}

var callReverseNameServer = function(url, server, limit){
    var api_params = Object.assign(DOMAINTOOLS_PARAMS, {"limit": limit? limit : 50})
    var reverse_ns_endpoint = `${url}/v1/${server}/name-server-domains/${encodeToURLQuery(api_params)}`
    var res = sendRequest(reverse_ns_endpoint)
    var md = 'Found ' +  res.response.primary_domains.length + ' domains\n';
    var context = {'Domain' : []};
    res.response.primary_domains.forEach(function(domain){
        md += '* ' + domain + '\n';
        context.Domain.push({'Name' : domain});
    });

    return {
        Type: entryTypes.note,
        Contents: res,
        ContentsFormat: formats.json,
        ReadableContentsFormat: formats.markdown,
        HumanReadable: md,
        EntryContext: context
    };
}

var callReverseWhoIs = function(url, args){
    args.api_username = params.username;
    args.api_key = params.key;
    args.mode = args.quoteMode;
    args.scope = 'current';
    if(args.onlyHistoricScope === 'true'){
        args.scope = 'historic';
    }
    delete args.quoteModel
    delete args.onlyHistoricScope;

    var api_params = Object.assign(DOMAINTOOLS_PARAMS, args)
    var reverse_whois_endpoint = `${url}/v1/reverse-whois/${encodeToURLQuery(api_params)}`

    var res = sendRequest(reverse_whois_endpoint);
    var context = {'Domain' : []};
    var md = 'Found '+res.response.domains.length+ ' domains: \n';
    res.response.domains.forEach(function(domain){
        md += '* ' + domain + '\n';
        context.Domain.push({'Name' : domain});
    });

    return {
        Type: entryTypes.note,
        Contents: res,
        ContentsFormat: formats.json,
        ReadableContentsFormat: formats.markdown,
        HumanReadable: md,
        EntryContext: context
    };
}

/*http://api.domaintools.com/v1/domaintools.com/whois/history/*/
var callWhoisHistory = function(url, domain){
    var whois_history_endpoint = `${url}/v1/${domain}/whois/history/${encodeToURLQuery(DOMAINTOOLS_PARAMS)}`
    var res = sendRequest(whois_history_endpoint)
    var splitRecord;
    var context = {'Domain' : {'Name' : domain, 'WhoisHistory' : []}};
    var md = '';
    var entryContext, record;
    res.response.history.forEach(function(entry){
        entryContext = {};
        record = entry.whois.record;
        if(record){
            var splitRecord = record.split('\n');
            splitRecord.forEach(function(pair){
                splitEntry = pair.split(/:\s(.+)/);
                    if(splitEntry[1]){
                        splitEntry[0] = toCamelCase(splitEntry[0]);
                        md += '**'+splitEntry[0]+':** '+splitEntry[1]+'\n';
                        entryContext[splitEntry[0]] = splitEntry[1];
                    }
            });
        }
        context.Domain.WhoisHistory.push(entryContext);
    });

    return {
        Type: entryTypes.note,
        Contents: res,
        ContentsFormat: formats.json,
        ReadableContentsFormat: formats.markdown,
        HumanReadable: md,
        EntryContext: context
    };
}

var url = params.server.replace(/[\/]+$/, '');
params.key = params.key || params.credentials.password
params.username = params.username || params.credentials.identifier
if (!params.key || !params.username) {
    throw 'Username and API key must be provided.'
}

const DOMAINTOOLS_PARAMS = {
    "api_username": params.username,
    "api_key": params.key,
    "app_partner": "cortex_xsoar",
    "app_name": "enterprise_for_xsoar",
    "app_version": "1"
}

switch (command) {
    case 'test-module':
            var account_url = `${url}/v1/account/${encodeToURLQuery(DOMAINTOOLS_PARAMS)}`
            var res = sendRequest(account_url)
            if(res.response.error){
                log('Something went wrong - error code ' + error.code);
            }
            return 'ok';
    case 'domain':
        return callDomain(url, args.domain, args.threshold);
    case 'domainSearch':
        return callDomainSearch(url, args);
    case 'reverseIP':
        return callReverseIP(url, args);
    case 'reverseNameServer':
        return callReverseNameServer(url, args.nameServer, args.limit);
    case 'reverseWhois':
        return callReverseWhoIs(url, args);
    case 'whois':
        return callWhoIs(url, args.query, args.parsed);
    case 'whoisHistory':
        return callWhoisHistory(url, args.domain);
    case 'domainProfile':
        return callProfile(url, args.domain);
}
