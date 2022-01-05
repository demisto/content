
var baseUrl = 'https://api.isightpartners.com'; // iSight base url
var publicKey = params.publicKey;
var privateKey = params.privateKey;
var acceptVersion = params.version;
var insecure = params.insecure;
var proxy = params.proxy;

var VENDOR_NAME = 'FireEye iSIGHT';

// we use this to map record-type to dbot-score
var intelligenceTypeToScore = {
    'overview': 1,
    'vulnerability': 2,
    'malware': 3,
    'threat': 3
};

// we use this to determine the order of reputation sevirity of the types
var intelligenceTypeOrder = ['overview', 'vulnerability', 'malware', 'threat'];

var epoch2DateStr = function(epochStr) {
    return new Date(parseInt(epochStr) * 1000).toString();
}

var createTableEntry = function (name, contents, table, context) {
    return {
        // type
        Type: entryTypes.note,
         // contents
        ContentsFormat: formats.json,
        Contents: contents,
        // human-readable
        ReadableContentsFormat: formats.markdown,
        HumanReadable: tableToMarkdown(name, table),
        // context
        EntryContext: context
    };
}

var getHeaders = function(query) {
    var timestamp = new Date().toUTCString();
    if (timestamp.indexOf('+') > 0) {
        timestamp = timestamp.substring(0,timestamp.indexOf('+'));
    } else if (timestamp.indexOf('-') > 0) {
        timestamp = timestamp.substring(0,timestamp.indexOf('-'));
    }
    message = query + acceptVersion + 'application/json' + timestamp;
    hashed = HMAC_SHA256_MAC(privateKey, message);

    return {
        'Accept': ['application/json'],
        'Accept-Version': [acceptVersion],
        'X-Auth': [publicKey],
        'X-Auth-Hash': [hashed],
        'Date': [timestamp]
    }
}

var sendRequest = function(query) {
    var headers = getHeaders(query);
    var requestUrl = baseUrl + query;

    var res = http(
        requestUrl,
        {
            Method: 'GET',
            Headers: headers,
            Body: ''
        },
        insecure,
        proxy
    );

    if (res.StatusCode < 200 || res.StatusCode >= 300) {
        throw 'Request Failed.\nUrl: ' + requestUrl + '\nStatus code: ' + res.StatusCode + '.\nResult: ' + JSON.stringify(res);
    }

    if (res.StatusCode === 204) {
        return [];
    }

    var body = JSON.parse(res.Body);
    if (!body || !body.success) {
        throw 'Request Failed.\nResonse body: ' + body;
    }
    return body;
};

var basicSearch = function(key, value) {
    var basicSearchQuery = '/search/basic?' + key + '=' + encodeURIComponent(value);
    var res = sendRequest(basicSearchQuery);
    return res.message;
}

var createContextReportsAndScore = function(records) {
    var dbotScore = 0;
    var highetsRecordType = 'None';
    var reports = [];

    // 1. set dbotScore to to the highest record-type among all records
    // 2. create report context-object for each record
    records && records.forEach(function(record) {
       var recordType = record['intelligenceType'];
       var recordScore =  intelligenceTypeToScore[recordType] || 0;
       if (dbotScore < recordScore) {
           dbotScore = recordScore;
       }
       if(intelligenceTypeOrder.indexOf(highetsRecordType) < intelligenceTypeOrder.indexOf(recordType)) {
           highetsRecordType = recordType;
       }
       var reportUrl = record['reportLink'];
       reports.push({
           ID: record['reportId'],
           title: record['title'],
           publishDate: epoch2DateStr(record['publishDate']),
           intelligenceType: recordType
       });
    });

    return {
        dbotScore: dbotScore,
        reports: reports,
        highetsRecordType: highetsRecordType
    }
}

var basicSearchIP = function(ip) {
    var records = basicSearch('ip', ip);

    if (!records) {
        return {
            Type: entryTypes.note,
            Contents: "No items match your search",
            ContentsFormat: formats.text,
            EntryContext: {
                DBotScore: {
                    Indicator: ip,
                    Type: 'IP',
                    Vendor: VENDOR_NAME,
                    Score: 0
                }
            }
        };
    }

    var res = createContextReportsAndScore(records);
    var context = {
        DBotScore: {Indicator: ip, Type: 'IP', Vendor: VENDOR_NAME, Score: res.dbotScore},
        'Report(val.ID && val.ID == obj.ID)': res.reports,
        'IP.Address': ip
    };

    if (res.dbotScore > 2) {
        addMalicious(context, outputPaths.ip,{
            Address: ip,
            Malicious: {Vendor: VENDOR_NAME, Description: 'IP was identified as ' + res.highetsRecordType}
        });
    }

    return createTableEntry("Results:", records, records, context);
}

var basicSearchDomain = function(domain) {
    var records = basicSearch('domain', domain);

    if (!records) {
        return {
            Type: entryTypes.note,
            Contents: "No items match your search",
            ContentsFormat: formats.text,
            EntryContext: {
                DBotScore: {
                    Indicator: domain,
                    Type: 'domain',
                    Vendor: VENDOR_NAME,
                    Score: 0
                }
            }
        };
    }

    var res = createContextReportsAndScore(records);
    var context = {
        DBotScore: {Indicator: domain, Type: 'domain', Vendor: VENDOR_NAME, Score: res.dbotScore},
        'Report(val.ID && val.ID == obj.ID)': res.reports,
        'Domain.Name': domain
    };

    if (res.dbotScore > 2) {
        addMalicious(context, outputPaths.domain,{
            Name: domain,
            Malicious: {Vendor: VENDOR_NAME, Description: 'domain was identified as ' + res.highetsRecordType}
        });
    }

    return createTableEntry("Results:", records, records, context);
}

var basicSearchfile = function(key, value) {
    var records = basicSearch(key, value);

    if (!records) {
        return {
            Type: entryTypes.note,
            Contents: "No items match your search",
            ContentsFormat: formats.text,
            EntryContext: {
                DBotScore: {
                    Indicator: value,
                    Type: 'file',
                    Vendor: VENDOR_NAME,
                    Score: 0
                }
            }
        };
    }

    var res = createContextReportsAndScore(records);
    var context = {
        DBotScore: {Indicator: value, Type: 'file', Vendor: VENDOR_NAME, Score: res.dbotScore},
        'Report(val.ID && val.ID == obj.ID)': res.reports
    };

    if (res.dbotScore > 2) {
        var malicuousObj = {
            Malicious: {
                Vendor: VENDOR_NAME,
                Description: 'file was identified as ' + res.highetsRecordType
            }
        };
        malicuousObj[key.toUpperCase()] = value;
        addMalicious(context, outputPaths.file, malicuousObj);
    }

    return createTableEntry("Results:", records, records, context);
}

var getReport = function(reportID) {
    var reportQuery = '/report/'+ encodeURIComponent(reportID);

    var res = sendRequest(reportQuery);
    var report = res.message.report;

    var context = {
        'Report(val.ID && val.ID == obj.ID)' : {
            ID: report.reportId,
            title: report.title,
            intelligenceType: report.intelligenceType,
            audience: report.audience,
            publishDate: report.publishDate,
            ThreatScape: report.ThreatScape.product,
            operatingSystems: report.operatingSystems,
            riskRating: report.riskRating,
            version: report.version,
            tagSection: report.tagSection
        }
    }

    var table = [{
        ID: report.reportId,
        title: report.title,
        intelligenceType: report.intelligenceType,
        audience: report.audience.join(),
        publishDate: report.publishDate,
        ThreatScape: report.ThreatScape.product.join(),
        operatingSystems: report.operatingSystems,
        riskRating: report.riskRating,
        version: report.version
    }];

    return createTableEntry("Report - " + reportID, res, table, context);
}

var submitFile = function(entryID, description, type) {
    var query = '/submit/data';
    var requestUrl = baseUrl + query;
    var headers = getHeaders(query);
    var res = httpMultipart(
            requestUrl, // URL
            entryID, // Optional - FilePath / EntryID
            { // HTTP Request Headers
                Method: 'POST',
                Headers: headers
            },
            { // Multipart Contents
                type: type,
                description: description
            },
            insecure,
            proxy
        );

    var statusCode = res && res.StatusCode;

    switch (statusCode) {
        case 200:
            return "The file was submitted sucessfully";
        case 403:
            throw "\nGot 403 error\nQuery valid but the response was refused because the user has exceeded their daily quota of submission requests";
        default:
            throw '\nSubmit File Failed.\nUrl: ' + requestUrl + '\nStatus code: ' + statusCode + '.\nResult: ' + JSON.stringify(res, null, 2);
    }
}

switch (command) {
    case 'test-module':
        basicSearch('ip', '66.34.253.56');
        return 'ok';
    case 'ip':
        return basicSearchIP(args.ip);
    case 'domain':
        return basicSearchDomain(args.domain);
    case 'file':
        var hash = args.file;
        var hashLength = hash && hash.length
        if(hashLength === 32) {
            return basicSearchfile('md5', hash);
        } else if(hashLength === 40) {
            return basicSearchfile('sha1', hash);
        } else {
            throw 'file argument must be md5(32 charecters) or sha1(40 charecters) ';
        }
    case 'isight-get-report':
        return getReport(args.reportID);
    case 'isight-submit-file':
        return submitFile(args.entryID, args.description, args.type);
}
