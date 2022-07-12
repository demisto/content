var server = params.server.replace(/[\/]+$/, '');
var username = params.credentials.identifier;
var password = params.credentials.password;
var insecure = params.insecure;
var proxy = params.proxy;

var sendRequest = function(method, url, body, apiKey) {
    var httpParams = {
            Method: method,
            Headers: {
                'Content-Type': ['application/json'],
                'X-Venafi-Api-Key': [apiKey]
            }
        };
    if (!apiKey) {
        delete(httpParams.Headers['X-Venafi-Api-Key']);
    }
    if (body) {
        httpParams.Body = body;
    }
    var res = http(server + url, httpParams, insecure, proxy, false);

    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        throw 'Request to Venafi Failed.\nStatus code: ' + res.StatusCode + '.\nBody: ' + JSON.stringify(res) + '.';
    }
    return JSON.parse(res.Body);
};

var auth = sendRequest('POST', '/VedSDK/Authorize/', JSON.stringify({ Username: username, Password: password }));
switch (command) {
    case 'test-module':
        if (auth) {
            return 'ok';
        }
        return 'something is wrong';
    case 'venafi-get-certificates':

        var raw = sendRequest('GET', '/vedsdk/certificates/' + encodeToURLQuery(args), undefined, auth.APIKey);

        var certs = [];
        for (var i in raw.Certificates) {
            certs.push({
                CreatedOn: raw.Certificates[i].CreatedOn,
                DN: raw.Certificates[i].DN,
                Name: raw.Certificates[i].Name,
                ParentDN: raw.Certificates[i].ParentDn,
                SchemaClass: raw.Certificates[i].SchemaClass,
                ID: raw.Certificates[i].Guid.substring(1, raw.Certificates[i].Guid.length - 1),
            });
        }
        var ec = {
            'Venafi.Certificats(val.ID==obj.ID)': certs,
            'Venafi.Certificate(val.ID==obj.ID)': certs
        };
        entry = {
            Type: entryTypes.note,
            Contents: raw,
            ContentsFormat: formats.json,
            ReadableContentsFormat: formats.markdown,
            EntryContext: ec,
            HumanReadable: tableToMarkdown('Venafi certificates query response', certs),
        };
        return entry;
    case 'venafi-get-certificate-details':

        var raw = sendRequest('GET', '/vedsdk/certificates/' + args.guid, undefined, auth.APIKey);
        raw.ParentDN = raw.ParentDn
        raw.ID = raw.Guid.substring(1, raw.Guid.length - 1)
        var ec = {
            'Venafi.Certificate(val.ID==obj.ID)': raw
        };

        entry = {
            Type: entryTypes.note,
            Contents: raw,
            ContentsFormat: formats.json,
            ReadableContentsFormat: formats.markdown,
            EntryContext: ec,
            HumanReadable: tableToMarkdown('Venafi certificates details', raw),
        };
        return entry;
    default:
        throw 'No can do';
}
