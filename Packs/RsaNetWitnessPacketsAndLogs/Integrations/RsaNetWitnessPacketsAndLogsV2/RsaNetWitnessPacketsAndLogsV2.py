import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
import traceback
from typing import Dict, Any

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


''' CONSTANTS '''

RESPONSE_TYPES = {
    'json': 'application/json',
    'html': 'text/html',
    'text': 'text/plain',
    'xml': 'text/xml',
    'octet-stream': 'application/octet-stream',
}

SSL_PORT = '56105'

NON_SSL_PORT = '50105'

LAST_HOURS = 'lastHours'

LAST_MINUTES = 'lastMinutes'

QUERY = 'query'


# // Check if concentrator IP and/or port were provided, if yes, then the url will be changed to the assigned concentrator.

# function getUrl(currentUrl){
#     var urlToReturn;
#     if(args && args.concentratorIP){
#         // Check if port was provided, omit it if yes
#         var match = args.concentratorIP.match(/(https{0,1}:\/\/?.*):/);
#         urlToReturn = match ? match[1] : args.concentratorIP;
#         var port = args.concentratorPort;
#         if(port){
#             if(port === SSL_PORT){
#                 urlToReturn = urlToReturn.indexOf('https://') === -1 ? 'https://' + urlToReturn : urlToReturn;
#             }
#             else{
#                 urlToReturn = urlToReturn.indexOf('http://') === -1 ? 'http://' + urlToReturn : urlToReturn;
#             }
#         }
#         else{
#             urlToReturn = urlToReturn.indexOf('http://') === -1 ? 'http://' + urlToReturn : urlToReturn;
#             port = NON_SSL_PORT;
#         }

#         urlToReturn = urlToReturn + ":" + port;

#         delete(args.concentratorIP);
#         delete(args.concentratorPort);
#     }
#     else {
#         urlToReturn = currentUrl;
#     }

#     return urlToReturn;
# }


# function isObjectEmpty(obj) {
#     for(var key in obj) {
#         if(obj.hasOwnProperty(key))
#             return false;
#     }
#     return true;
# }


# /* Example transformation:
#     {
#     "fields": [
#         {
#             "count": 0,
#             "flags": 0,
#             "format": 8,
#             "group": 13,
#             "id1": 504,
#             "id2": 504,
#             "type": "sessionid",
#             "value": "13"
#         },
#         {
#             "count": 0,
#             "flags": 0,
#             "format": 32,
#             "group": 13,
#             "id1": 505,
#             "id2": 505,
#             "type": "time",
#             "value": 1372882420
#         },
#         {
#             "count": 0,
#             "flags": 0,
#             "format": 6,
#             "group": 13,
#             "id1": 506,
#             "id2": 506,
#             "type": "size",
#             "value": "16452"
#         },
#         {
#             "count": 0,
#             "flags": 0,
#             "format": 6,
#             "group": 13,
#             "id1": 507,
#             "id2": 507,
#             "type": "payload",
#             "value": "13590"
#         },
#         {
#             "count": 0,
#             "flags": 0,
#             "format": 2,
#             "group": 13,
#             "id1": 508,
#             "id2": 508,
#             "type": "medium",
#             "value": "1"
#         }
#     ],
#     "id1": 509,
#     "id2": 3938
# }


# To:


# {
#     sessionid: 13,
#     paylod: 13590,
#     size: 16542,
#     time: 1372882420
# }


# */


# function mapQueryResults(fields, queryResults) {
#     var TYPE  = 'type';
#     var VALUE = 'value';
#     var GROUP = 'group';
#     if(fields && Array.isArray(fields)) {
#         fields.forEach(function (element) {
#             if (element[TYPE] && element[VALUE]) {
#                 var index = element[GROUP] || 0;
#                 if(!(queryResults[index])){
#                     queryResults[index] = {};
#                 }
#                 // Dot to camel case
#                 var type = element[TYPE].replace(/\.([a-z,A-Z,0-9])/g, function (g) {
#                     return g[1].toUpperCase();
#                 });

#                 if(!(queryResults[index][type])) {
#                     queryResults[index][type] = element[VALUE];
#                 }
#                 else{
#                     if(!(queryResults[index][type] instanceof Array)){
#                         var currValue = queryResults[index][type];
#                         // Ignore duplicates
#                         if(currValue !== element[VALUE]){
#                             queryResults[index][type] = [currValue];
#                             queryResults[index][type].push(element[VALUE]);
#                         }
#                     }
#                     else {
#                         // Ignore duplicates
#                         if(queryResults[index][type].indexOf(element[VALUE]) === -1){
#                             queryResults[index][type].push(element[VALUE]);
#                         }
#                     }
#                 }
#             }
#         });
#     }
# }


# /*

# Example transformation:

# {
#     "fields": [
#         {
#             "count": 1,
#             "flags": 0,
#             "format": 65,
#             "group": 0,
#             "id1": 25,
#             "id2": 25,
#             "type": "client",
#             "value": "opera mail/12.11"
#         },
#         {
#             "count": 5,
#             "flags": 0,
#             "format": 65,
#             "group": 0,
#             "id1": 13,
#             "id2": 63,
#             "type": "client",
#             "value": "mozilla/5.0"
#         },
#         {
#             "count": 31,
#             "flags": 0,
#             "format": 65,
#             "group": 0,
#             "id1": 14,
#             "id2": 61,
#             "type": "client",
#             "value": "mozilla/4.0"
#         },
#         {
#             "count": 2,
#             "flags": 0,
#             "format": 65,
#             "group": 0,
#             "id1": 5,
#             "id2": 6,
#             "type": "client",
#             "value": "e1e8d428-5bf1-4323-8808-d138a039102f"
#         }
#     ],
#     "id1": 0,
#     "id2": 0
# }


# To:


# [
#     {
#         client: opera mail/12.11
#     },
#     {
#         client: mozilla/5.0,
#     },
#     {
#         client: mozilla/4.0,
#     },
#     {
#         client: e1e8d428-5bf1-4323-8808-d138a039102f
#     }
# ]

# */


# function mapArrayResults(fields, arrayResults){
#     var TYPE  = 'type';
#     var VALUE = 'value';
#     if(fields && Array.isArray(fields)) {
#         fields.forEach(function (element) {
#             var currObject = {};
#             // Dot to camel case ip.src => ipSrc
#             // The reason for this transformation is to allow use in context
#             var type = element[TYPE].replace(/\.([a-z,A-Z,0-9])/g, function (g) {
#                 return g[1].toUpperCase();
#             });
#             currObject[type] = element[VALUE];
#             arrayResults.push(currObject);
#         });
#     }
# }


# function extractFromData(data, mapper, results){
#     if (Array.isArray(data)) {
#         data.forEach(function (element) {
#             var fields = dq(element, 'results.fields');
#             mapper(fields, results);
#         });
#     } else if ((typeof data) ==='object') {
#         var fields = dq(data, 'results.fields');
#         mapper(fields, results);
#     }
# }


# function buildQueryMdAndContext(response) {
#     var data = parseResponse(response);

#     var queryResults = {};
#     extractFromData(data, mapQueryResults, queryResults);
#     var flatQueryResult = [];
#     if(!isObjectEmpty(queryResults)) {
#         for(var key in queryResults) {
#             flatQueryResult.push(queryResults[key]);
#         }
#         var hr = tableToMarkdown(command, flatQueryResult);
#         return {
#             Type: entryTypes.note,
#             Contents: data,
#             ContentsFormat: formats.json,
#             HumanReadable: hr,
#             EntryContext: {
#                 'NetWitness.Events': flatQueryResult
#             },
#             ReadableContentsFormat: formats.markdown
#         };
#     } else {
#         return "No results found.";
#     }
# }


# function buildMSearchMdAndContext(response) {
#     var data = parseResponse(response);

#     var queryResults = {};
#     extractFromData(data, mapQueryResults, queryResults);
#     var flatQueryResult = [];
#     if(!isObjectEmpty(queryResults)) {
#         for(var key in queryResults) {
#             flatQueryResult.push(queryResults[key]);
#         }
#         var hr = tableToMarkdown(command, flatQueryResult);
#         return {
#             Type: entryTypes.note,
#             Contents: data,
#             ContentsFormat: formats.json,
#             HumanReadable: hr,
#             EntryContext: {
#                 'NetWitness.SearchHits': flatQueryResult
#             },
#             ReadableContentsFormat: formats.markdown
#         };
#     } else {
#         return "No results found.";
#     }
# }


# function buildValuesMdAndContext(response) {
#     var data = parseResponse(response);

#     var arrayResults = [];
#     extractFromData(data, mapArrayResults, arrayResults);
#     if(arrayResults.length !== 0) {
#     var typeDict = {};
#             for(var index in arrayResults){
#                 var type = Object.keys(arrayResults[index])[0];
#                 if(!typeDict[type]){
#                     typeDict[type] = [];
#                 }

#                 typeDict[type].push(arrayResults[index][type]);
#             }
#             var arr = [];
#             var maxLength = 0;
#             for(var key in typeDict){
#                 if(maxLength < typeDict[key].length){
#                     maxLength = typeDict[key].length;
#                 }
#             }

#             for(var i = 0; i < maxLength; i++){
#                 var currObj = {};
#                 for(var key in typeDict){
#                     currObj[key] = typeDict[key][i];
#                 }
#                 if(!isObjectEmpty(currObj)){
#                     arr.push(currObj);
#                 }
#             }

#             var hr = tableToMarkdown(command, arr);
#             return {
#                 Type: entryTypes.note,
#                 Contents: data,
#                 ContentsFormat: formats.json,
#                 HumanReadable: hr,
#                 EntryContext: {
#                     'NetWitness.Values': arrayResults
#                 },
#                 ReadableContentsFormat: formats.markdown
#             };
#     } else {
#         return "No results found.";
#     }
# }


# function buildTimelineMdAndContext(response) {
#     var data = parseResponse(response);

#     var arrayResults = [];
#     extractFromData(data, mapArrayResults, arrayResults);
#     if(arrayResults.length !== 0) {
#         var hr = tableToMarkdown(command, arrayResults);
#         return {
#             Type: entryTypes.note,
#             Contents: data,
#             ContentsFormat: formats.json,
#             HumanReadable: hr,
#             EntryContext: {
#                 'NetWitness.Timeline': arrayResults
#             },
#             ReadableContentsFormat: formats.markdown
#         };
#     } else {
#         return "No results found.";
#     }
# }

# function buildNodeMdAndContext(response){
#     var data = parseResponse(response);
#     var nodes = data.nodes ? data.nodes : [data.node];

#     return {
#         Type: entryTypes.note,
#         Contents: nodes,
#         ContentsFormat: formats.json,
#         HumanReadable: tableToMarkdown(command, nodes),
#         EntryContext: {
#             'NetWitness.Node(val.handle==obj.handle)' : nodes
#         },
#         ReadableContentsFormat: formats.markdown
#     };
# }


# function buildStringMdAndContext(response){
#     var data = parseResponse(response);
#     var string = data.string;
#     var md =  '### Results for ' + command + ':\n' + string;
#     return {
#         Type: entryTypes.note,
#         Contents: data,
#         ContentsFormat: formats.json,
#         HumanReadable: md
#     };
# }


# function buildParamsMd(response){
#     var data = parseResponse(response);
#     var resultParams= data.params;

#     return {
#         Type: entryTypes.note,
#         Contents: data,
#         ContentsFormat: formats.json,
#         HumanReadable: tableToMarkdown(command, resultParams)
#     };
# }


# function buildDatabaseMetaMdContext(response){
#     var data = parseResponse(response);
#     var resultParams = data.params;
#     if(!resultParams || resultParams.length === 0){
#         return 'No results found';
#     }

#     // First element of the response
#     var metaArray = resultParams[0]['MetaArray'];
#     var dbFile = resultParams[0]['dbFile'];

#     results = {};

#     mapQueryResults(resultParams, results);
#     var flattenedResult = [];
#     for(var key in results){
#         results[key]['MetaArray'] = metaArray;
#         results[key]['dbFile'] = dbFile;
#         flattenedResult.push(results[key]);
#     }

#     return {
#         Type: entryTypes.note,
#         Contents: data,
#         ContentsFormat: formats.json,
#         HumanReadable: tableToMarkdown('Database dump meta', flattenedResult),
#         EntryContext: {
#             'NetWitness.DatabaseDump(val.sessionid == obj.sessionid)': flattenedResult
#         },
#         ReadableContentsFormat: formats.markdown
#     };
# }


# function parseResponse(resp, isXml) {
#     if (resp.StatusCode === 200) {
#         try {
#             var body = resp.Body;
#             if(isXml){
#                 body = x2j(body);
#             }
#             var res = JSON.parse(body);

#             return res;
#         } catch (e) {
#             return body;
#         }
#     } else {
#         err = resp.Status;
#         if (resp.Body) {
#             err += '\n' + resp.Body;
#         }
#         throw err;
#     }
# }


# function createFileEntry(data, extension){
#     var currentTime = new Date();
#     var fileName = command + '_at_' + currentTime.getTime();
#     if(extension){
#         fileName += extension;
#     }

#     return {
#         Type: 3,
#         FileID: saveFile(data),
#         File: fileName,
#         Contents: fileName
#     };
# }


# function parseDownloadResponse(resp) {
#     if (resp.StatusCode === 200) {
#         try {
#             var extension;
#             if(args && args.fileExt){
#                 extension = args.fileExt;
#             }
#             return createFileEntry(resp.Bytes, extension);
#         } catch (e) {
#             return e;
#         }
#     } else {
#         err = resp.Status;
#         if (resp.Body) {
#             err += '\n' + resp.Body;
#         }
#         throw err;
#     }
# }


# function handleTimeFilter(args) {
#     if(LAST_HOURS in args || LAST_MINUTES in args) {
#         var now = new Date();
#         var dt = new Date();
#         if (args[LAST_HOURS]) {
#             dt.setHours(dt.getHours() - parseInt(args[LAST_HOURS]))
#         }
#         if (args[LAST_MINUTES]) {
#             dt.setMinutes(dt.getMinutes() - parseInt(args[LAST_MINUTES]))
#         }
#         var buildDateFormat = function () {
#             return dt.toISOString().slice(0,19).replace('T',' ') + '"-"' + now.toISOString().slice(0,19).replace('T',' ') + '"';
#         };
#         //if query is empry string
#         if(!args || !args[QUERY]) {
#             args[QUERY] = 'select * where time = "' + buildDateFormat();
#         }
#         //query must have select statement
#         else if(args[QUERY].toLowerCase().indexOf('select') > -1) {
#             sql_query = args[QUERY].toLowerCase().split('group by');

#             if (sql_query[0].toLowerCase().indexOf('where') > -1)
#                 args[QUERY] = sql_query[0] + ' && time = "' + buildDateFormat();
#             else
#                 args[QUERY] = sql_query[0] + ' where time = "' + buildDateFormat();

#             if (sql_query.length > 1)
#                 args[QUERY] += ' group by ' + sql_query[1].trim();
#         }
#     }
# }


# function encodeParams(p) {
#     var q = '';
#     if (p) {
#         var argsToIgnore = {
#             responseType: true,
#             using: true
#         };
#         handleTimeFilter(p);
#         var keys = Object.keys(p);
#         if (keys.length > 0) {
#             q = '&';
#             for (var i = 0; i < keys.length; i++) {
#                 if (argsToIgnore[keys[i]]) {
#                     continue;
#                 } else if (i !== 0) {
#                     q += '&';
#                 }
#                 q += encodeURIComponent(keys[i]) + '=' + encodeURIComponent(p[keys[i]]);
#             }
#         }
#     }
#     return q;
# }


# function doReq(method, path, args, responseType, body) {
#     var parametersUrl = encodeParams(args);
#     var fullUrl = BASE_URL + path + parametersUrl;
#     if(responseType){
#         fullUrl += ('&force-content-type=' + responseType);
#     }

#     if (params.expiry) {
#         fullUrl += '&expiry=' + params.expiry;
#     }

#     var res = http(
#         fullUrl,
#         {
#             Method: method,
#             Username: USER_NAME,
#             Password: PASSWORD,
#             Accept: responseType || '',
#             Body: body || ''
#         },
#         !params.secure,
#         params.proxy
#     );

#     if (res.StatusCode !== 200 && res.StatusCode !== 201) {
#         throw 'Failed to perform request to: ' + fullUrl + '. StatusCode: ' + res.StatusCode + '. Status: ' + res.Status + '. Error: ' + res.Body;
#     }

#     return res;
# }


# function decoderImport(path) {
#     var fileParam = args.entryID ? args.entryID : args.fileID;
#     var fullUrl = BASE_URL + path;
#     var res = httpMultipart(
#         fullUrl,
#         fileParam,
#         { // HTTP Request Headers
#             Method: 'POST',
#             ContentType: 'appliaction/json',
#             Accept: 'application/json',
#             Username: USER_NAME,
#             Password: PASSWORD
#         },
#         null,
#         !params.secure,
#         params.proxy
#     );

#     var data = parseResponse(res, true);

#     return {
#         Type: entryTypes.note,
#         Contents: data,
#         ContentsFormat: formats.json,
#         HumanReadable: tableToMarkdown(command, data.import.data)
#     };

# }


# var commandToPath = {
#     'netwitness-packets': ,
#     'nw-sdk-session': ,
#     'nw-sdk-content': ,
#     'nw-sdk-summary': ,
#     'nw-sdk-values': ,
#     'nw-database-dump': ,
# };


# // The command input arg holds the command sent from the user.

# switch (command) {
#     case 'netwitness-msearch':
#         return ;
#     case 'netwitness-query':
#         return buildQueryMdAndContext();
#     case 'nw-sdk-packets':
#         return parseDownloadResponse();
#     case 'nw-sdk-session':
#         return buildParamsMd();
#     case 'nw-sdk-content':
#         return parseDownloadResponse();
#     case 'nw-sdk-summary':
#         return buildStringMdAndContext();
#     case 'nw-sdk-values':
#         return buildValuesMdAndContext();
#     case 'nw-database-dump':
#         return buildDatabaseMetaMdContext();
# }


''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def __init__(self, base_url, user_name, password, verify, proxy):
        super().__init__(
            base_url,
            verify=verify,
            proxy=proxy,
            auth=(user_name, password),
            headers={
                'Accept': 'application/json; charset=UTF-8',
            },
        )
        # self._user_name = user_name
        # self._password = password

    def netwitness_msearch(self, args: Dict[str, str]) -> CommandResults:
        args['msg'] = 'msearch'
        return self._http_request('GET', '/sdk', params=args)
        # doReq('GET', '/sdk?msg=msearch', args, RESPONSE_TYPES['json'])


    def netwitness_query(self, args: Dict[str, str]) -> CommandResults:
        # doReq('GET', '/sdk?msg=query', args, RESPONSE_TYPES['json'])
        pass


    def netwitness_packets(self, args: Dict[str, str]) -> CommandResults:
        return self._http_request('GET', 'sdk/packets', params=args, resp_type='content')


    def nw_sdk_session(self, args: Dict[str, str]) -> CommandResults:
        args['msg'] = 'session'
        return self._http_request('GET', '/sdk', params=args)


    def nw_sdk_content(self, args: Dict[str, str]) -> CommandResults:
        # doReq('GET', '/sdk/?msg=content', args, RESPONSE_TYPES['octet-stream'])
        pass


    def nw_sdk_summary(self, args: Dict[str, str]) -> CommandResults:
        # doReq('GET', '/sdk?msg=summary', args, RESPONSE_TYPES['json'])
        pass


    def nw_sdk_values(self, args: Dict[str, str]) -> CommandResults:
        # doReq('GET', '/sdk?msg=values', args, RESPONSE_TYPES['json'])
        pass


    def nw_database_dump(self, args: Dict[str, str]) -> CommandResults:
        # doReq('GET', '/database?msg=dump', args, RESPONSE_TYPES['json'])
        pass


''' HELPER FUNCTIONS '''

# TODO: ADD HERE ANY HELPER FUNCTION YOU MIGHT NEED (if any)

''' COMMAND FUNCTIONS '''


def test_module_command(client: Client, _) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    client._http_request('GET', 'rest/stats')
    return 'ok'

def netwitness_msearch_command(client: Client, args: Dict[str, str]) -> CommandResults:
    # buildMSearchMdAndContext()
    results = client.netwitness_msearch()

    return CommandResults(
        readable_output=tableToMarkdown('', results),
        # outputs=results
        raw_response=results,
    )


def netwitness_query_command(client: Client, args: Dict[str, str]) -> CommandResults:
    results = client.netwitness_query()

    return CommandResults(
        readable_output=tableToMarkdown('', results),
        # outputs=results
        raw_response=results,
    )


def netwitness_packets_command(client: Client, args: Dict[str, str]) -> CommandResults:
    results = client.netwitness_packets()

    return CommandResults(
        readable_output=tableToMarkdown('', results),
        # outputs=results
        raw_response=results,
    )


def nw_sdk_session_command(client: Client, args: Dict[str, str]) -> CommandResults:
    results = client.nw_sdk_session(args)

    return CommandResults(
        readable_output=tableToMarkdown('nw-sdk-session', results.get('params')),
        # outputs=results
        raw_response=results,
    )


def nw_sdk_content_command(client: Client, args: Dict[str, str]) -> CommandResults:
    results = client.nw_sdk_content()

    return CommandResults(
        readable_output=tableToMarkdown('', results),
        # outputs=results
        raw_response=results,
    )


def nw_sdk_summary_command(client: Client, args: Dict[str, str]) -> CommandResults:
    results = client.nw_sdk_summary()

    return CommandResults(
        readable_output=tableToMarkdown('', results),
        # outputs=results
        raw_response=results,
    )


def nw_sdk_values_command(client: Client, args: Dict[str, str]) -> CommandResults:
    results = client.nw_sdk_values()

    return CommandResults(
        readable_output=tableToMarkdown('', results),
        # outputs=results
        raw_response=results,
    )


def nw_database_dump_command(client: Client, args: Dict[str, str]) -> CommandResults:
    results = client.nw_database_dump()

    return CommandResults(
        readable_output=tableToMarkdown('', results),
        # outputs=results
        raw_response=results,
    )


''' MAIN FUNCTION '''


def main():
    # #=====================================================================================================================
    # # COMMON CONFIGURATIONS FOR CLIENTS
    # #=====================================================================================================================

    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    commands = {
        'test-module': test_module_command,
        'netwitness-msearch': netwitness_msearch_command,
        'netwitness-query': netwitness_query_command,
        'netwitness-packets': netwitness_packets_command,
        'nw-sdk-session': nw_sdk_session_command,
        'nw-sdk-content': nw_sdk_content_command,
        'nw-sdk-summary': nw_sdk_summary_command,
        'nw-sdk-values': nw_sdk_values_command,
        'nw-database-dump': nw_database_dump_command,
    }

    # #=====================================================================================================================
    # # Client Initialization
    # #=====================================================================================================================

    try:

        # # Create client instances
        client = Client(
            params.get('base_url'),
            params.get('credentials', {}).get('identifier'),
            params.get('credentials', {}).get('password'),
            not params.get('insecure'),
            handle_proxy(),
        )
        # Attempt Login
        # client.doLogin()
        # processed_args = process_args(client, args)

        # demisto.info(f'\n\ndates:\n{client.getTimeRange()}\n\n')

        if command in commands:
            command_func = commands[command]
            return_results(command_func(client, args))

    except Exception as exc:
        return_error(f'Failed to run the {command} command. Error:\n{exc}', error=traceback.format_exc())


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
