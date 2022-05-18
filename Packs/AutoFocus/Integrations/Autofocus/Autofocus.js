var SERVER = params.server.replace(/[\/]+$/, '') + '/api/' + params.version + '/';

function doReq(path, data) {
    data.apiKey = params.apiKey;
    var result = http(
        SERVER + path,
        {
            Headers: {'Content-Type': ['application/json'], 'Accept': ['application/json']},
            Method: 'POST',
            Body: JSON.stringify(data)
        },
        params.insecure,
        params.useproxy
    );

    if (result.StatusCode < 200 || result.StatusCode > 299) {
        if (result.StatusCode == 503) {
            throw '503 - Rate limit exceeded. Contact your Autofocus representative.';
        }
        if (result.StatusCode == 409) {
            throw '409 - Invalid message or missing parameters.';
        }
        else {
            throw 'Failed to perform request ' + path + ', request status code: ' + result.StatusCode + '\n' + result.Body;
        }
    }
    if (result.Body === '') {
        throw 'No content received.';
    }
    var obj;
    try {
        obj = JSON.parse(result.Body);
    } catch (ex) {
        throw 'Error parsing reply - ' + result.Body + ' - ' + ex;
    }
    return {
        body: result.Body,
        obj: obj,
        statusCode: result.StatusCode
    };
}


function doSearch(prefix) {
    var cookie = args.cookie;
    if (!cookie) {
        var q = {};
        q.query = JSON.parse(args.query);
        q.from = parseInt(args.from);
        q.size = parseInt(args.size);
        if (args.sort) {
            q.sort = {};
            q.sort[args.sort] = {order: (args.order ? args.order : 'asc')};
        }
        if (args.scope) {
            q.scope = args.scope;
        }
        var res = doReq(prefix + '/search/', q);
        if (!res.obj.af_cookie) {
            throw 'Unable to retrieve cookie of search results';
        }
        cookie = res.obj.af_cookie;
    }
    var checks = (args.checks) ? parseInt(args.checks) : 10;
    var sleep = (args.sleep) ? parseInt(args.sleep) : 3;
    var res1;
    var ec = {'Autofocus.Cookie': cookie};
    while (checks > 0) {
        checks--;
        wait(sleep);
        res1 = doReq(prefix + '/results/' + cookie, {});
        if (res1.obj.af_message === 'complete' || res1.obj.af_in_progress === false ||
                (res1.obj.hits && res1.obj.hits.length >= parseInt(args.size))) {
            var md = '## PAN Autofocus ' + prefix + ' result\n';
            md += 'Total: ' + res1.obj.total + '\nTook: ' + res1.obj.took + '\n';
            var hits = [];
            for (var i=0; i<res1.obj.hits.length; i++) {
                var data = res1.obj.hits[i]._source;
                data.id = res1.obj.hits[i]._id;
                hits.push(data);
            }
            ec['Autofocus.S' + prefix.substr(1)] = hits;
            md += tableToMarkdown('S' + prefix.substr(1), hits);
            return {
                Type: entryTypes.note,
                Contents: res1.body,
                ContentsFormat: formats.json,
                HumanReadable: md,
                EntryContext: ec
            };
        }
    }
    return {
        Type: entryTypes.note,
        Contents: ec,
        ContentsFormat: formats.json,
        HumanReadable: 'PAN Autofocus timeout occured waiting for results, cookie is: ' + cookie,
        EntryContext: ec
    };
}


function doSession(id) {
    var res = doReq('session/' + id, {});
    if (res.obj.af_message === 'complete' || res.obj.af_in_progress === false || res.obj.hits.length >= 1) {
        var hits = [];
        for (var i=0; i<res.obj.hits.length; i++) {
            var data = res.obj.hits[i]._source;
            data.id = res.obj.hits[i]._id;
            hits.push(data);
        }
        md = tableToMarkdown('PAN Autofocus session details', hits);
        md += 'Took: ' + res.obj.took + '\n';
        return {
            Type: entryTypes.note,
            Contents: res.body,
            ContentsFormat: formats.json,
            HumanReadable: md,
            EntryContext: {'Autofocus.Sessions': hits}
        };
    }
    return {
        Type: entryTypes.note,
        ContentsFormat: formats.markdown,
        Contents: 'PAN Autofocus no session for: ' + id
    };
}


function doSample() {
    var p = {};
    if (args.sections) {
        p.sections = argToList(args.sections);
    }
    if (args.platforms) {
        p.platforms = argToList(args.platforms);
    }
    if (args.coverage === 'true') {
        p.coverage = true;
        if (p.sections && p.sections.indexOf('coverage') < 0) {
            p.sections.push('coverage');
        }
    }
    var res = doReq('sample/' + args.id + '/analysis', p);
    md = '## PAN Autofocus Sample Analysis\n';
    md += '### Sections: ' + res.obj.sections.join(', ') + '\n';
    md += '### Platforms: ' +  res.obj.platforms.join(', ') + '\n';
    if (res.obj.coverage) {
        Object.keys(res.obj.coverage).forEach(function(s) {
            if (Object.keys(res.obj.coverage[s]).length) {
                md += tableToMarkdown('Coverage ' + s, res.obj.coverage[s]) + '\n';
            }
        });
    }
    res.obj.sections.forEach(function(s) {
        if (s === 'coverage') {
            return;
        }
        res.obj.platforms.forEach(function(p) {
            if (res.obj[s][p]) {
                md += tableToMarkdown(s + ' - ' + p, res.obj[s][p]) + '\n';
            }
        });
    });
    return {
        Type: entryTypes.note,
        Contents: res.body,
        ContentsFormat: formats.json,
        HumanReadable: md
    };
}

switch (command) {

    case 'test-module':
        doReq('samples/search/', {query: {operator: 'all', children: [{field: 'sample.malware', operator: 'is', value: 1}]}, size: 1, from: 0, scope: 'public'});
        return 'ok';

    case 'autofocus-search-samples':
        return doSearch('samples');

    case 'autofocus-search-sessions':
        return doSearch('sessions');

    case 'autofocus-session':
        return doSession(args.id);

    case 'autofocus-sample-analysis':
        return doSample(args.id);

    case 'file':
        args.size = 1;
        args.from = 0;
        args.scope = 'public';
        var hash = args.file.length === 64 ? 'sha256' : args.file.length === 40 ? 'sha1' : 'md5';
        args.query = JSON.stringify({operator: 'all', children: [{field: 'sample.' + hash, operator: 'is', value: args.file}]});
        var search = doSearch('samples');
        if (search.EntryContext && search.EntryContext['Autofocus.Samples'] && search.EntryContext['Autofocus.Samples'].length > 0) {
            var c = search.EntryContext['Autofocus.Samples'][0];
            var dbotScore = [];
            ['md5', 'sha1', 'sha256'].forEach(function(h) {
                if (c[h]) {
                    dbotScore.push({Indicator: c[h], Type: 'hash', Vendor: 'PAN Autofocus', Score: c.malware === 1 ? 3 : 1,
                        Description: c.tag && c.tag.length > 0 ? c.tag.join(', ') : c.malware === 1 ? 'Marked as malware' : ''});
                }
            });
            var ec = {DBotScore: dbotScore};
            var f = {MD5: c.md5, SHA1: c.sha1, SHA256: c.sha256, Size: c.size, SSDeep: c.ssdeep, Region: c.region ? c.region.join(',') : '', Info: c.filetype, Type: c.filetype};
            if (c.malware === 1) {
                f.properties_to_append = ['Malicious'];
                f.Malicious = {Vendor: 'PAN Autofocus', Description: dbotScore[0].Description};
            }
            ec[outputPaths.file] = f;
            // Now, let's add any interesting sessions we've encountered to the display
            args.size = 50;
            delete args.scope;
            args.query = JSON.stringify({operator: 'all', children: [{field: 'session.sha256', operator: 'is', value: c.sha256}]});
            var md = search.HumanReadable;
            var sessions = doSearch('sessions');
            if (sessions.EntryContext && sessions.EntryContext['Autofocus.Sessions'] && sessions.EntryContext['Autofocus.Sessions'].length > 0) {
                md += '\n' + sessions.HumanReadable;
            }
            return {
                Type: entryTypes.note,
                Contents: search.Contents,
                ContentsFormat: formats.json,
                HumanReadable: md,
                EntryContext: ec
            };
        }
        return {
            Type: entryTypes.note,
            ContentsFormat: formats.markdown,
            Contents: 'PAN Autofocus no data for: ' + args.file
        };

    default:
        throw 'Unknown command "' + command + '"';
}
