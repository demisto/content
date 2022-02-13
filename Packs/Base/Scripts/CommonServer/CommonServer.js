// Common functions script
// =======================
// This script will be appended to each server script before being executed.
// Place here all common functions you'd like to share between server scripts.


// ============= Fix vault credentials =============
// =================================================
try {
    if(params && typeof params === 'object'){
        for(var key in params){
            param = params[key];
            if(typeof param === 'object' && 'credentials' in param  && param.credentials.vaultInstanceId){
                param.identifier = param.credentials.user;
            }
        }
    }
}
catch (e) {}
// =================================================

/**
 * Returns true if string starts with search string
 * @param {String} search - The string to be searched
 * @param {Integer} pos - The position in this string at which to begin searching for search string; defaults to 0.
 * @return {Boolean} true if string starts with <search> string
 */
if (!String.prototype.startsWith) {
    String.prototype.startsWith = function(search, pos) {
        return this.substr(!pos || pos < 0 ? 0 : +pos, search.length) === search;
    };
}

/**
 * Returns true if string ends with search string
 * @param {String} search - The string to be searched
 * @param {Integer} this_len - Optional. If provided it is used as the length of search string. If omitted, the default value is the length of the string.
 * @return {Boolean} true if string ends with <search> string
 */
if (!String.prototype.endsWith) {
    String.prototype.endsWith = function(search, this_len) {
        if (this_len === undefined || this_len > this.length) {
            this_len = this.length;
        }
        return this.substring(this_len - search.length, this_len) === search;
    };
}

/**
 * Removes the final slash / from the given url. This function should be used to prevent double slash situations such as https://192.12.12.3:8443//api/
 *
 * @param {String} url - e.g https://some_url.com:8080/ or https://some_url.com:8080
 * @return {String} url without slash in the end - e.g https://some_url.com:8080
 */
function fixUrl(url) {
    if (url.endsWith('/')) {
        return url.slice(0, -1);
    }

    return url;
}
/**
 * Removes the final slash / from the given url. This function should be used to prevent double slash situations such as https://192.12.12.3:8443//api/
 *
 * @param {String} url - e.g https://some_url.com:8080/ or https://some_url.com:8080
 * @return {String} url without slash in the end - e.g https://some_url.com:8080
 */
var removeLastSlash = fixUrl;

/**
 * Formats a string in place
 * @return {String} The formatted string
 */
String.prototype.format = function() {
   var content = this;
   for (var i=0; i < arguments.length; i++)
   {
        var replacement = '{' + i + '}';
        content = content.replace(replacement, arguments[i]);
   }
   return content;
}

cleanSingleObject = function(contents) {
    var cleanContents = {};
    var keys = Object.keys(contents);
    for (var i = 0; i < keys.length; i++) {
        if (contents[keys[i]] || contents[keys[i]] === false) {
            cleanContents[keys[i]] = contents[keys[i]];
        }
    }
    return cleanContents;
}

/**
 * Clean an object from empty fields
 * @param {Object} obj - The object to be cleaned
 * @return {Object} The cleaned object
 */
var cleanObject = function(obj) {
    if (obj instanceof Array) {
        var res = [];
        for (var j in obj) {
            res.push(cleanObject(obj[j]));
        }
        return res;
    }
    return cleanSingleObject(obj);
}

/**
  * Merge a list of objects into a single object.
  * Note: to avoid loss of data, use only on objects with foreign properties.
  * @param {Array} objs - An array of arrays to be merged
  * @return {Object} the merged array
  */
function mergeForeignObjects(objs) {
    var merged = {};
    for (var i in objs) {
        for (var j in objs[i]) {
            merged[j] = objs[i][j];
        }
    }
    return merged;
}

/**
 * Creates a string from an object
 * @param {JSON | String} o - The object to create the string from
 * @param {String} [delimiter] - The delimiter of the string representation of arrays
 * @return {String} A string which represents the object
 */
function objToStr(o, delimiter) {
    if(!delimiter || typeof(delimiter) !== 'string') {
              delimiter = ',';
          }
    if (Array.isArray(o)) {
        return o.map(function(v) {
            return objToStr(v);
        }).join(delimiter);
    } else if (typeof(o) === 'string') {
        return o;
    } else if (typeof(o) === 'number') {
        return '' + o;
    } else {
        return JSON.stringify(o);
    }
}

MARKDOWN_CHARS = "\\`*_{}[]()#+-!|"

/**
 * Escapes markdown characters in a string
 * @param {String} st - The string to fix
 * @param {Boolean} [replaceNewlines] - Should newlines be replaced with '<br>'
 * @return {String} A string with the markdown characters escaped
 */
var stringEscapeMD = function(st, replaceNewlines, minimal_escaping) {
    if (typeof(st) != 'string') {
        return st;
    }

    if (replaceNewlines) {
      st = st.replace(/\r\n/g, '<br>');
      st = st.replace(/\n/g, '<br>');
      st = st.replace(/\r/g, '<br>');
    }

    var escapedSt = '';
    if (minimal_escaping) {
        escapedSt = st.replace(/\|/g, '\\|');
    } else {
        for (var i = 0; i < st.length; i++) {
            if (MARKDOWN_CHARS.indexOf(st[i]) > -1) {
                escapedSt += '\\';
            }
            escapedSt += st[i];
        }
    }

    return escapedSt;
};

var HTML_ENTITY_MAP = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
  '/': '&#x2F;',
  '`': '&#x60;',
  '=': '&#x3D;'
};

/**
 * Escapes html characters in a string
 * @param {String} st - The string to fix
 * @return {String} A string with the html characters escaped
 */
var stringEscapeHTML = function(st) {
    return String(st).replace(/[&<>"'`=\/]/g, function (s) {
        return HTML_ENTITY_MAP[s];
    });
}

/**
 * Converts textual keys to pascal format (e.g. "Threat Score" -> "ThreatScore")
 * @param {Object} dict - The object to be converted
 * @return {Object} The converted object
 */
var convertKeysToPascalCase = function(dict) {
    var pascalDict = {};
    for (var key in dict) {
        var pascalCaseKey = key.replace(/\w+/g, function(w) { return w[0].toUpperCase() + w.slice(1).toLowerCase(); }).replace(/ /g, '');
        pascalDict[pascalCaseKey] = dict[key];
    }

    return pascalDict;
}

/**
 * Gets a parameter that can be either an array, a JSON array or a string list separated by ',' and returns an array
 * @param {Object} [arg] - The object to be converted
 * @return {Array} An array representing the given object
 */
function argToList(arg) {
    if (!arg) {
        return [];
    }
    if (Array.isArray(arg)) {
        return arg;
    }
    if (typeof(arg) === 'string') {
        if (arg[0] === '[' && arg[arg.length - 1] === ']') {
            return JSON.parse(arg);
        }
        return arg.split(',');
    }
    return arg;
}

/**
 * Converts a JSON demisto table to a Markdown table
 * @param {String} name - The name of the table
 * @param {Object} t - the JSON table - Array of objects with the same keys
 * @param {Array|String} [headers] - The output markdown table will show only these headers (by order). Use a single string in case of a value type array (Optional).
 * @param {String} [cellDelimiter] - The delimiter of the string representation of arrays (Optional).
 * @param {Function} [headerTransform] - A transformation function for the header keys in the markdown table (Optional).
 * @return {String} A string representing the markdown table
 */
function tableToMarkdown(name, t, headers, cellDelimiter, headerTransform) {
    if (t && !(t instanceof Array)){
        t = [t];
    }

    if(headers && !(headers instanceof Array) && typeof(headers) !== 'object'){
        headers = [headers];
    }

    //in case of headers was not provided (backward compatibility)
    if ((!(headers) || !(headers instanceof Array) || headers.length === 0) && t && t.length > 0 && typeof(t[0]) === 'object') {
        headers = GetAllObjectsProperties(t);
    }

    if(!headers || !(headers instanceof Array) || headers.length === 0) {
        return 'No data returned\n';
    }

    var mdResults = '';
    if (name) {
        mdResults = '### ' + name + '\n';
    }
    if (t && t.length) {
        var newHeaders = [];
        if(!headerTransform){
          headerTransform = function(string){return string;};
        }
        for(var i=0; i<headers.length; i++){
            newHeaders.push(headerTransform(headers[i]));
        }
        if (newHeaders.length > 1) {
            mdResults += newHeaders.join('|') + '\n';
        } else {
            mdResults += newHeaders[0] + '|' + '\n';
        }
        var sep = [];
        headers.forEach(function(h){
            sep.push('---');
        });
        if (sep.length === 1) {
            sep[0] = sep[0]+'|';
        }
        mdResults += sep.join('|') + '\n';
        t.forEach(function(entry){
            var vals = [];
            if(typeof(entry) !== 'object' && !(entry instanceof Array)){
              var obj = {};
              obj[headers[0]] = entry;
              entry = obj;
            }
            headers.forEach(function(h){
                if(entry[h] === null || entry[h] === undefined) {
                    vals.push(' ');
                } else {
                    vals.push(stringEscapeMD(formatCell(entry[h], cellDelimiter), true, true) || ' ');
                }
            });
            if (vals.length === 1) {
                vals[0] = vals[0]+'|';
            }
            mdResults += vals.join(' | ') + '\n';
        });
    } else{
        mdResults += 'No data returned\n';
    }
    return mdResults;
}

var tblToMd = tableToMarkdown;


/**
 * Converts an array of stings to markdown table
 * @param {Array} arr - from strings
 * @param {String} [header] - The output markdown table will show only these headers (by order) (Optional).
 * @return {String} A markdown string of tables. If input array was empty, will return "No results" instead.
 */
function arrayToMarkdownTable(arr, header) {
  if (!arr) {
      return 'No results';
  }
  if (!Array.isArray(arr)) {
      throw arr + ' is not an array';
  }
  if (arr.length === 0) {
      return 'No results';
  }

  if (typeof arr[0] === 'object') {
      throw 'arrayToMarkdownTable should receive arr which contain objects but simple types like string, int, bool'
  }
  if (!header) {
      throw 'header is required for arrayToMarkdownTable';
  }

  var md = '|' + header + '|\n-';
  arr.forEach(function(item) {
      md += '\n|' + item + '|';
  });

  return md;
}

/**
 * Converts underscore case strings to camel case
 * @param {String} string - The string to be converted - i.e. hello_world
 * @return {String} - The converted string - i.e. HelloWorld
*/
var underscoreToCamelCase = function(string) {
    var ret_string = '_'+string;
    return ret_string.replace(/_([a-z])/g, function (g) { return g[1].toUpperCase(); });
};

/**
 * Converts dots into spaces and capitalizes
 * @param {String} string - The string to be converted - i.e. hello.world
 * @return {String} - The converted string - i.e. Hello World
*/
var dotToSpace = function(string) {
    var ret_string = '.'+string;
    return ret_string.replace(/\.([a-z,A-Z])/g, function (g) { return ' '+g[1].toUpperCase(); });
};

/**
 * Converts pascal strings to human readable (e.g. "ThreatScore" -> "Threat Score")
 * @param {String} string - The string to be converted
 * @return {String} - The converted string
*/
var pascalToSpace = function(string) {
    return string.replace(/([a-z][A-Z])/g, function (g) { return g[0] + ' ' + g.slice(1); });
};

function mapObjFunction(mapFields, filter) {
    var transformSingleObj= function(obj) {
        var res = {};
        mapFields.forEach(function(f) {
            if(!filter || filter(f)){
                res[f.to] = dq(obj, f.from);
            }
        });
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

function createContext(data, id) {
    var createContextSingle = function(obj) {
        var res = {};
        var keys = Object.keys(obj);
        keys.forEach(function(k) {
            var values = k.split('.');
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

var isFunction = function(functionToCheck) {
    return functionToCheck && typeof functionToCheck === 'function';
}

/**
 * Creates a dq query string. Used by easyDQ.
 * @param {string} path - the path to be parsed
 * @param {function | string} filter - filter string (e.g. 'val.id===<some id>'') or filter function (e.g. function(obj){return obj.name === 'name';} )
 * @param {function | string} returnValue - string or function that defines returned data format (e.g. '{Name : val.name}' or function(val){return {Name:val.name};} )
 * @return {string} - the query string to pass to dq function
*/
var dqQueryBuilder = function(path, filter, returnValue){
    var query = path;
    if(!filter){
        filter = 'true';
    }
    if(isFunction(filter)){
        filter = filter.toString() + '(val)';
    }
    if(typeof filter !== 'string'){
        throw 'dqQueryBuilder: Filter type is neither a function nor a string';
    }
    query += '('+filter+')';
    if(returnValue){
        if(isFunction(returnValue)){
            returnValue = returnValue.toString() + '(val)';
        }
        if(typeof returnValue !== 'string'){
            throw 'dqQueryBuilder: return value for DQ is neither a function nor a string';
        }
        query += '='+returnValue;
    }
    return query;
};

/**
 * Creates a dq query from arguments and calls dq
 * @param {Object} data - The raw data object
 * @param {String} path - The path to be parsed
 * @param {Function | String} filter - A filter string (e.g. 'val.id===<some id>'') or a filter function (e.g. function(obj){return obj.name === 'name';} )
 * @param {Function | String} returnValue - string or function that defines the returned data format (e.g. '{Name : val.name}' or function(val){return {Name:val.name};} )
 * @return {Object} - The value returned from the dq function
*/
easyDQ = function(data, path, filter, returnValue){
    return dq(data, dqQueryBuilder(path, filter, returnValue));
};

/* creates array from obj, if obj is not already an array */
var toArray = function(obj){
    if(obj && !Array.isArray(obj))
        return [obj];
    return obj;
};

/**
 * Creates a war room entry
 * @param {Object} result - The raw result to be parsed
 * @param {Object} translator - Maps raw data to the war room output. Should be of the following format:
 * ```
 * {
 *   contextPath: <context-path>,
 *   title: <war-room-title>,
 *   data: [
 *     {to: <dest-key>, from: <orig-key>, (optional) humanReadable: <true/false>},
 *     {to: <dest-key>, from: <orig-key>, (optional) humanReadable: <true/false>},
 *     ...
 *   ]
 * }
 * ```
 * - dest-key/orig-key should be sparated with '.' (e.g. 'File.Malicious')
 * - dest-key is also used for war room table headers
 * - humanReadable states whether field should appear in war room table. Default is true.
 * @param {function} [MDfilter] - (optional) filters out fields that shouldn't be displayed in warroom (returns true/false). Default uses humanReadable field.
 * @param {function} [headerTransform] - transform mark down headers to readable format.
 * @return {Object} - the war room entry
*/
var createEntry = function(result, translator, MDfilter, headerTransform) {
    /* filters out all fields where humanReadable is false */
    var filter = function(obj) {
        if(obj.humanReadable !== false) {
            return true;
        }
        return false;
    };
    if (MDfilter) {
        filter = MDfilter;
    }

    var entry = {
        Type: entryTypes.note,
        Contents: result,
        ContentsFormat: formats.json,
        ReadableContentsFormat: formats.markdown
    };

    var content = translator.innerPath ? dq(result, translator.innerPath) : result;
    var translatedContext = mapObjFunction(translator.data) (content);
    var translatedMD = mapObjFunction(translator.data, filter) (content);
    entry.HumanReadable = tableToMarkdown(translator.title, translatedMD, undefined, undefined, headerTransform || dotToSpace);
    entry.EntryContext = {};
    var context = createContext(translatedContext);
    entry.EntryContext[translator.contextPath] = context;
    return entry;
};

/**
 * Converts a demisto table in JSON form to a HTML table
 * @param {String} name - the name of the table
 * @param {Object} t - the JSON table - Array of objects with the same keys
 * @param {Array} [headers] - optional, the output markdown table will show only these headers (by order)
 * @param {String} [cellDelimiter] - The delimiter of the string representation of arrays (Optional).
 * @return {String} A string representation of the html result
 */
function tableToHTML(name, t, headers, cellDelimiter) {
    if (t && !(t instanceof Array)){
        t = [t];
    }

    //in case of headers was not provided (backward compatibility)
    if ((!headers || !headers instanceof Array || headers.length === 0) && t && t.length > 0){
        headers = GetAllObjectsProperties(t);
    }

    if(!headers || !headers instanceof Array || headers.length === 0) {
        return 'No data returned<br/>';
    }

    var htmlResults = '';
    if (name) {
        htmlResults = '<h3>' + name + '</h3>';
    }
    if (t && t.length) {
        htmlResults += '<table border="1" cellspacing="0" cellpadding="3"><tr>' + headers.reduce(function(acc, v) {return acc + '<th>' + v + '</th>';}, '') + '</tr>';
        t.forEach(function(entry){
            var vals = [];
            headers.forEach(function(h){
                vals.push((!!entry[h] || entry[h]==0) ? stringEscapeHTML(formatCell(entry[h], cellDelimiter)) : ' ');
            });
            htmlResults += '<tr>' + vals.reduce(function(acc, v) {return acc + '<td>' + v + '</td>';}, '') + '</tr>';
        });
        htmlResults += '</table>';
    } else{
        htmlResults += 'No data returned<br/>';
    }
    return htmlResults;
}

/**

* Verifies that the given fields exists in the content and verifies its value
* @param {String} fieldName - the name of the field (dq format)
* @param {Object} expectedValue - the value to verify
* @param {String} [comparisonType] - 'stringContains' or 'stringEquals'. Default is 'stringEquals'
* @return {Object} Returns the value if value at the field matches, throws an error an exeption otherwise
*/
function verifyContextField(fieldName, expectedValue, comparisonType) {
    value = dq(invContext, fieldName);

    if (value === undefined) {
        throw 'Field does not exist: {0}.'.format(fieldName);
    }

    if (expectedValue !== undefined) {
        if (comparisonType == 'stringContains') {
            if (value.indexOf(expectedValue) == -1) {
                throw 'Field {0} does not contain the expected string. Value: {1}, expected: {2}.'.format(fieldName, value, expectedValue);
            }
        } else {
            if (value != expectedValue) {
                throw 'Field {0} does not match. Value: {1}, expected: {2}.'.format(fieldName, value, expectedValue);
            }
        }
    }

    return value;
}

/**
 * Get all properties of objects in an array.
 * @param {Array} t - Array of elements
 * @return {Array} - Array of object properties
*/
function GetAllObjectsProperties(t) {
    var properties = {};
    t.forEach(function (element) {
        for(var prop in element) {
            properties[prop] ='';
        }
    });
    return Object.keys(properties).sort();
}

/**
 * Checks if the given string represents a valid IPv4 address
 * @deprecated please use isValidIP which really checks IP for validity
 * @param {String} ip - the string to check
 * @return {Boolean} true if valid IPv4 address
 */
function isIp(ip) {
  var d = ip.split('.'), i = d.length;
  if (i !== 4) {
    return false;
  }
  var ok = true;
  while (i-- && ok) {
    ok = d[i].length !== 0 && !isNaN(parseInt(d[i])) && d[i] > -1 && d[i] < 256;
  }
  return ok;
}

var entryTypes = {note: 1, downloadAgent: 2, file: 3, error: 4, pinned: 5, userManagement: 6, image: 7, plagroundError: 8, playgroundError: 8, entryInfoFile: 9, map: 15, widget: 17};
var formats = {html: 'html', table: 'table', json: 'json', text: 'text', dbotResponse: 'dbotCommandResponse', markdown: 'markdown'};
// The object below does not represent DBot Scores correctly, and should not be used
var dbotscores = {critical : 4, high: 3, medium: 2, low: 1, informational: 0.5, unknown: 0};

/**
 * Returns the name of the file as stored in our investigation artifacts on disk.
 * This should be used when sending files to d2 scripts as you can see in StaticAnalyze.
 * @param {String} entryId - The entry ID containing the file
 * @return {String} The name of the file in our artifact repository
 */
function fileNameFromEntry(entryId) {
  var parts = entryId.split('@');
  if (parts.length !== 2) {
    return null;
  }
  var res = executeCommand('getEntry', {id: entryId});
  if (res && Array.isArray(res) && res.length === 1) {
    return parts[1] + '_' + res[0].FileID;
  }
  return null;
}

/**
 * Closes the current investigation
 * @param {Object} args - Closing details (what happened, damage, etc.)
 * @return {Array} An array with an error entry if an error occurred, an empty array otherwise
 */
function closeInvestigation(args) {
  return executeCommand('closeInvestigation', args);
}

/**
 * Sets severity an incident. The incident must be related to current investigation.
 * @param {Object} arg - Has 2 keys, 'id' - the incident id, 'severity' - the new severity value (Critical, High, Medium etc.).
 * @return {Array} An array with an error entry if an error occurred, an empty array otherwise
 */
function setSeverity(arg) {
  return executeCommand('setSeverity', arg);
}

/**
 * Sets fields of the incident. The incident must be related to current investigation and be the only incident in it.
 * @param {Object} args - Has 5 optional keys: type, severity, details, name and systems of the incident.
 *                        systems should follow this string template: '1.1.1.1,10.10.10.10'
 * @return {Array} An array with an error entry if an error occurred, an empty array otherwise
 */
function setIncident(args) {
  return executeCommand('setIncident', args);
}

/**
 * Create a new incident with the fields specified, only if an incident with the same name does not exist as an active incident.
 * If an active incident with the same name exists, ignore the request.
 * @param {Object} args - Has 5 optional keys: type, severity, details, name and system of the incident.
 * @return {Array} An array with an error entry if an error occurred, an empty array otherwise
 */
function createNewIncident(args) {
  return executeCommand('createNewIncident', args);
}

/**
 * Sets playbook according to type.
 * @param {String} type - The incident type, according to which the playbook is chosen
 * @return {Array} An array with an error entry if an error occurred, an empty array otherwise
 */
function setPlaybookAccordingToType(type) {
  return executeCommand('setPlaybookAccordingToType', {type: type});
}

/**
 * Sets Owner to an incident. The incident must be related to current investigation.
 * @param {Object} name - The user name of the owner
 * @return {Array} An array with an error entry if an error occurred, an empty array otherwise
 */
function setOwner(name) {
  return executeCommand('setOwner', { owner: name });
}

/**
 * Assigns a playbook task to a user.
 * @param {Object} arg - Has 2 keys, 'id' - the task id, 'assignee' - the user name of the assignee.
 * @return {Array} An array with an error entry if an error occurred, an empty array otherwise
 */
function taskAssign(arg) {
  return executeCommand('taskAssign', arg);
}

/**
 * Sets task due date.
 * @param {Object} arg - Has 2 keys, 'id' - the task id, 'dueDate' - time string in UTC format (To get current time use: 'new Date().toUTCString()').
 * @return {Array} An array with an error entry if an error occurred, an empty array otherwise
 */
function setTaskDueDate(arg) {
  return executeCommand('setTaskDueDate', arg);
}

/**
 * Sets investigation playbook
 * @param {String} name - The playbook name.
 * @return {Array} An array with an error entry if an error occurred, an empty array otherwise
 */
function setPlaybook(name) {
  return executeCommand('setPlaybook', { name: name });
}

/**
 * Adds task to Workplan
 * @param {Object} arg - has 5 keys:
 * - 'name' - (mandatory) The new task's name.
 * - 'description' - (optional) The new task's description.
 * - 'script' - (optional) Name of script to be run by task.
 * - 'addBefore' - (optional, refers to task id) Insert new task before specified task (when using this argument do not use afterTask)
 * - 'addAfter' - (optional, refers to task id) Insert new task after specified task (when using this argument do not use beforeTask)
 * @return {Array} An array with an error entry if an error occurred, an empty array otherwise
 */
function addTask(arg) {
  return executeCommand('addTask', arg);
}

/**
 * Encode json object to URL. Supports multiple arguments of the same value if input is an array.
 * @param {Object} args - The object to encode.
 * @return {String} in case of error will be empty. In Case of success will return the URL string.
 */
function encodeToURLQuery(args) {
      var query = '';
      if (args) {
          var keys = Object.keys(args);
          if (keys.length > 0) {
              query = '?';
              for (var i = 0; i<keys.length; i++) {
                  if (i !== 0) {
                      query += '&';
                  }
                  if (Array.isArray(args[keys[i]])) {
                      for (var j=0; j<args[keys[i]].length; j++) {
                          if (j !== 0) {
                              query += '&';
                          }
                          query += encodeURIComponent(keys[i]) + '=' + encodeURIComponent(args[keys[i]][j]);
                      }
                  } else {
                      query += encodeURIComponent(keys[i]) + '=' + encodeURIComponent(args[keys[i]]);
                  }
              }
          }
      }
      return query;
}

/**
 * Translate ThreatConnect rating to score
 * @param {rating} TC rating as int
 * @return {score} Int (between 0 and 3)
 */
function threatConnectRatingToScore(rating) {
    var tcScore = 0;
    if (rating == 2 || rating == 1) {
        tcScore = 2;
    }
    if (rating > 2) {
        tcScore = 3;
    }
    return tcScore;
}

/**
* Check the list of available modules to see whether a command is currently available to be run.
* @param {Object} cmd - The command to check.
* @return {bool} True if command is available, false otherwise
*/
function isCommandAvailable(cmd) {
    var all = getAllSupportedCommands();
    var modules = Object.keys(all);
    for(var i = 0; i < modules.length ; i++) {
        var modCmds = all[modules[i]];
        if (modCmds) {
            for(var j = 0; j < modCmds.length ; j++) {
                if (modCmds[j].name === cmd) {
                    return true;
                }
            }
        }
    }
    return false;
}

/**
 * Check if the given entry is an error entry
 * @param {Object} entry - The entry to check
 * @return {Boolean} True if this is an error entry, false otherwise
 */
function isError(entry) {
  return entry && typeof entry === 'object' && entry.Type === entryTypes.error;
}

/**
 * Check if the given result entry is an array and is not an error
 * @param {Array} res - The result from the execute to check
 * @return {Boolean} True if this is a valid result
 */
function isValidRes(res) {
  return res && Array.isArray(res) && res.length && !isError(res[0]);
}

/**
 * If the given value exists, return it. Otherwise, return default and if not provided 'Unknown'
 * @param {Object} v - Value that can be anything
 * @param {Object} [def] - Default value. If not provided will be 'Unknown'
 * @return {Object} Value if exists, default otherwise
 */
function nvl(v, def) {
  return v ? v : def ? def : 'Unknown';
}

/**
 * Flatten the fields into a map of dot notation key and value
 * @param {Object} obj - The object to iterate on
 * @param {String} [path] - (optional) The path so far in dot notation
 * @param {Object} flat - The collected object result
 * @return {Object} An object with keys that are dot notation and values
 */
function flattenFields(obj, path, flat) {
  if (obj) {
      if (typeof obj === 'object') {
          var keys = Object.keys(obj);
          for (var f=0; f<keys.length; f++) {
              flattenFields(obj[keys[f]], !!path ? path + '.' + keys[f] : keys[f], flat);
          }
      } else if (Array.isArray(obj)) {
          for (var i=0; i<obj.length; i++) {
              flattenFields(obj[i], !!path ? path + '.' + i : '' + i, flat);
          }
      } else {
          flat[path] = obj.toString();
      }
  }
}

var formatCell = objToStr;

/**
 * Convert a given object to md while descending multiple levels
 * @param {Object} o - The object to convert - can be an array as well
 * @return {String} - The converted markdown string
 */
function objToMd(o) {
    var flat = {};
    flattenFields(o, '', flat);
    var keys = Object.keys(flat);
    keys.sort();
    var md = 'Key | Value\n- | -\n';
    for (var i=0; i<keys.length; i++) {
        md += keys[i] + ' | ' + flat[keys[i]] + '\n';
    }
    return md;
}

/**
 * Convert a given object to md list (-) while each value is converted to a simple string
 * @param {Object} o - The object to convert
 * @param {String} t - The title of the list
 * @return {String} The markdown string
 */
function objToList(o, t) {
  var md = '';
  if (o) {
      md += '### ' + t + '\n';
      var keys = Object.keys(o);
      for (var i=0; i<keys.length; i++) {
          md += '- ' + keys[i] + ': ' + objToStr(o[keys[i]]) + '\n';
      }
  }
  return md;
}

/**
* Converts the given timestamp to a string
* @param {int} timestamp - The timestamp in UNIX format
* @return {String} A string representing the time - e.g. 'Thu, 11 May 2017 11:18:56 UTC'
*/
function convertTimestampToString(timestamp) {
  return (new Date(parseInt(timestamp))).toISOString();
}

/**
* Converts the given number (uint32) to an IP address string
* @param {int} num -  The number to convert
* @return {String} A string representing the IP address - e.g. '192.168.2.1'
*/
var numToIp = function(num) {
  var ip = num % 256;

  for (var i = 3; i > 0; i--) {
      num = Math.floor(num / 256);
      ip = num % 256 + '.' + ip;
  }

  return ip;
}

/**
 * Convert a given array to a markdown table
 * @param {Array} arr - The array to convert
 * @return {String} - The converted markdown string
 */
function arrToMd(arr) {
    if (!arr || arr.length === 0) {
        return '';
    }
    return tableToMarkdown('', arr);
}

/**
 * Query the given object with the given path and retrive it
 * @deprecated please use dq which has the full functionality
 * @param {Object} obj - The object to query
 * @param {String} path - The path to retrieve from the object
 * @return {Object} The value of the path if the path exists, null otherwise
 */
function jq(obj, path) {
  if (!obj || !path || (typeof obj !== 'object' && !Array.isArray(obj))) {
    return null;
  }
  var parts = path.split('.');
  for (var i=0; i<parts.length; i++) {
    // First, handle array option
    var part = parts[i].match(/([a-zA-Z0-9_]*)(\[([0-9]+)\])?/);
    if (part[3]) {
      // If array of property and not top array
      if (part[1]) {
        if (obj.hasOwnProperty(part[1]) && Array.isArray(obj[part[1]])) {
          obj = obj[part[1]][parseInt(part[3])];
        } else {
          return null;
        }
      } else {
        if (Array.isArray(obj)) {
          obj = obj[parseInt(part[3])];
        } else {
          return null;
        }
      }
    } else {
      // Not an array
      if (obj.hasOwnProperty(part[1])) {
        obj = obj[part[1]];
      } else {
        return null;
      }
    }
  }
  return obj;
}

/**
 * Replace the given args with the actual values in the input template
 * @param {String} input - The template to replace values in
 * @param {Object} args - The map of values to use
 * @return {String} The template with the values filled in
 */
function replaceInTemplates(input, args) {
  var res = input;
  var keys = Object.keys(args);
  for (var i = 0; i < keys.length; i++) {
    res = res.split('%' + keys[i] + '%').join(args[keys[i]]);
  }
  return res;
}

/**
 * Replace the given args with the actual values in the input template and remove from args
 * @param {String} input - The template to replace values in
 * @param {Object} args - The map of values to use
 * @return {String} the template with the values filled in
 */
function replaceInTemplatesAndRemove(input, args) {
    var res = input;
    var keys = Object.keys(args);
    for (var i = 0; i < keys.length; i++) {
      if (res.indexOf('%' +  keys[i] + '%') !== -1) {
        res = res.split('%' + keys[i] + '%').join(args[keys[i]]);
        delete(args[keys[i]]);
      }
    }
    return res;
}

var xmlReservedChars = {
  '&': '&amp;',
  '\"': '&quot;',
  '\'': '&apos;',
  '<': '&lt;',
  '>': '&gt;'
};

/**
 * Escape reserved XML chars in the input
 * @param {String} input - The input to escape
 * @return {String} The escaped input
 */
function escapeXMLChars(input) {
    var res = input;
    var keys = Object.keys(xmlReservedChars);
    for (var i = 0; i < keys.length; i++) {
        res = res.split(keys[i]).join(xmlReservedChars[keys[i]]);
    }
    return res;
}

/**
 * Convert a string representing a comma separated list into an array
 * @param {String} listName - The name of the list
 * @return {Array} The list as an array
 */
function getCSVListAsArray(listName) {
    var res = executeCommand('getList', {listName: listName});
    if (isValidRes(res)) {
        var data = res[0].Contents.split(',');
        return data.filter(function(v) {return v;}).map(function(v) {return v.trim();});
    }
    return [];
}

/**
 * Convert a JSON list/array into an object
 * @param {String} listName - The name of the list
 * @return {Object} The JSON as an object
 */
function getJSONListAsObject(listName) {
    var res = executeCommand('getList', {listName: listName});
    if (isValidRes(res)) {
        try {
            return JSON.parse(res[0].Contents);
        } catch (ex) {
            throw 'Error parsing list - ' + res[0].Contents + ' - ' + ex;
        }
    }
    return null;
}

var brands = {xfe: 'xfe', vt: 'VirusTotal', cy: 'cylance', wf: 'WildFire', cs: 'crowdstrike-intel', threatconnect: 'ThreatConnect'};
var providers = {xfe: 'IBM X-Force Exchange', vt: 'VirusTotal', cy: 'Cylance', wf: 'WildFire', cs: 'CrowdStrike'};
// Thresholds for the various reputation services to mark something as positive
var thresholds = {xfeScore: 3, vtPositives: 10, vtPositiveUrlsForIP: 10};

/**
 * Checks if the given entry from a URL reputation query is positive (known bad)
 * @deprecated
 * @param {Object} entry - reputation entry
 * @return {Boolean} true if positive, false otherwise
 */
function positiveUrl(entry) {
  if (entry.Type !== entryTypes.error && entry.ContentsFormat === formats.json) {
    var c = entry.Contents;
    if (entry.Brand === brands.xfe && c && c.url.result.score && c.url.result.score > thresholds.xfeScore) {
      return true;
    } else if (entry.Brand === brands.vt && c && c.positives && c.positives > thresholds.vtPositives) {
      return true;
    } else if (entry.Brand === brands.cs && c && c.length && c[0].indicator && (c[0].malicious_confidence === 'high' || c[0].malicious_confidence === 'medium')) {
      return true;
    }
  }
  return false;
}

/**
 * Checks if the given entry from a file reputation query is positive (known bad)
 * @deprecated
 * @param {Object} entry - reputation entry
 * @return {Boolean} true if positive, false otherwise
 */
function positiveFile(entry) {
  if (entry.Type !== entryTypes.error && entry.ContentsFormat === formats.json) {
    var c = entry.Contents;
    if (entry.Brand === brands.xfe && c && c.malware.family) {
      return true;
    } else if (entry.Brand === brands.vt && c && c.positives && c.positives > thresholds.vtPositives) {
      return true;
    } else if (entry.Brand === brands.wf && c && c.wildfire && c.wildfire.file_info) {
      return c.wildfire.file_info.malware === 'yes';
    } else if (entry.Brand === brands.cy && c) {
      var k = Object.keys(c);
      if (k && k.length > 0) {
        var v = c[k[0]];
        if (v && v.generalscore) {
          return v.generalscore < -0.5;
        }
      }
    } else if (entry.Brand === brands.cs && c && c.length && c[0].indicator && (c[0].malicious_confidence === 'high' || c[0].malicious_confidence === 'medium')) {
      return true;
    }
  }
  return false;
}

/**
 * Checks if the given entry from an IP reputation query is positive (known bad)
 * @deprecated
 * @param {Object} entry - reputation entry
 * @return {Boolean} true if positive, false otherwise
 */
function positiveIP(entry) {
  if (entry.Type !== entryTypes.error && entry.ContentsFormat === formats.json) {
    var c = entry.Contents;
    if (entry.Brand === brands.xfe && c && c.reputation.score && c.reputation.score > thresholds.xfeScore) {
      return true;
    } else if (entry.Brand === brands.vt && c && c.detected_urls) {
      var positives = 0;
      for (var i = 0; i < c.detected_urls.length; i++) {
        if (c.detected_urls[i].positives > thresholds.vtPositives) {
          positives++;
        }
      }
      return positives > thresholds.vtPositiveUrlsForIP;
    } else if (entry.Brand === brands.cs && c && c.length && c[0].indicator && (c[0].malicious_confidence === 'high' || c[0].malicious_confidence === 'medium')) {
      return true;
    }
  }
  return false;
}

/**
 * Display CrowdStrike Intel results in Markdown
 * @deprecated
 * @param {Object} entry - reputation entry
 * @return {Object} the markdown entry
 */
function shortCrowdStrike(entry) {
  if (entry.Type !== entryTypes.error && entry.ContentsFormat === formats.json) {
    var c = entry.Contents;
    if (entry.Brand === brands.cs && c && c.length && c[0].indicator) {
      var csRes = '## CrowdStrike Falcon Intelligence';
      csRes += '\n\n### Indicator - ' + c[0].indicator;
      if (c[0].labels && c[0].labels.length) {
        csRes += '\n### Labels';
        csRes += '\nName|Created|Last Valid';
        csRes += '\n----|-------|----------';
        for (var l = 0; l < c[0].labels.length; l++) {
          csRes += '\n' + c[0].labels[l].name + '|' + new Date(c[0].labels[l].created_on * 1000) + '|' + new Date(c[0].labels[l].last_valid_on * 1000);
        }
      }
      if (c[0].relations && c[0].relations.length) {
        csRes += '\n### Relations';
        csRes += '\nIndicator|Type|Created|Last Valid';
        csRes += '\n---------|----|-------|----------';
        for (var r = 0; r < c[0].relations.length; r++) {
          csRes += '\n' + c[0].relations[r].indicator + '|' + c[0].relations[r].type + '|' + new Date(c[0].relations[r].created_date * 1000) + '|' + new Date(c[0].relations[r].last_valid_date * 1000);
        }
      }
      return {ContentsFormat: formats.markdown, Type: entryTypes.note, Contents: csRes};
    }
  }
  return entry;
}

/**
 * Formats a URL reputation entry into a short table
 * @deprecated
 * @param {Object} entry - reputation entry
 * @return {Object} the table entry
 */
function shortUrl(entry) {
  if (entry.Type !== entryTypes.error && entry.ContentsFormat === formats.json) {
    var c = entry.Contents;
    if (entry.Brand === brands.xfe && c) {
      return {ContentsFormat: formats.table, Type: entryTypes.note, Contents: {
        Country: c.country, MalwareCount: c.malware.count, A: c.resolution.A ? c.resolution.A.join(',') : '',
        AAAA: c.resolution.AAAA ? c.resolution.AAAA.join(',') : '', Score: c.url.result.score,
        Categories: c.url.result.cats ? Object.keys(c.url.result.cats).join(',') : '',
        URL: c.url.result.url, Provider: providers.xfe, ProviderLink: 'https://exchange.xforce.ibmcloud.com/url/' + c.url.result.url
      }};
    } else if (entry.Brand === brands.vt && c) {
      return {ContentsFormat: formats.table, Type: entryTypes.note, Contents: {
        ScanDate: c.scan_date, Positives: c.positives, Total: c.total, URL: c.url, Provider: providers.vt, ProviderLink: c.permalink
      }};
    } else if (entry.Brand === brands.cs && c && c.length && c[0].indicator) {
      return shortCrowdStrike(entry);
    } else if (entry.Brand === brands.threatconnect && c && c.data && c.data.url) {
      var url = c.data.url;
      return {ContentsFormat: formats.table, Type: entryTypes.note, Contents: {
        Url: url.text, Rating: url.rating, Confidence: url.confidence,
        DateAdded: url.dateAdded, ID: url.id, webLink: url.webLink, Provider: entry.Brand
      }};
    }
  }
  return entry;
}

/**
 * Formats a file reputation entry into a short table
 * @deprecated
 * @param {Object} entry - reputation entry
 * @return {Object} the table entry
 */
function shortFile(entry) {
  if (entry.Type !== entryTypes.error && entry.ContentsFormat === formats.json) {
    var c = entry.Contents;
    if (entry.Brand === brands.xfe && entry.Contents) {
      var cm = c.malware;
      return {ContentsFormat: formats.table, Type: entryTypes.note, Contents: {
        Family: cm.family, MIMEType: cm.mimetype, MD5: cm.md5 ? cm.md5.substring(2) : '',
        CnCServers: cm.origins.CnCServers.count, DownloadServers: cm.origins.downloadServers.count,
        Emails: cm.origins.emails.count, ExternalFamily: cm.origins.external && cm.origins.external.family ? cm.origins.external.family.join(',') : '',
        ExternalCoverage: cm.origins.external.detectionCoverage, Provider: providers.xfe,
        ProviderLink: 'https://exchange.xforce.ibmcloud.com/malware/' + cm.md5.replace(/^(0x)/,"")
      }};
    } else if (entry.Brand === brands.vt && entry.Contents) {
      return {ContentsFormat: formats.table, Type: entryTypes.note, Contents: {
        Resource: c.resource, ScanDate: c.scan_date, Positives: c.positives, Total: c.total, SHA1: c.sha1, SHA256: c.sha256, Provider: providers.vt, ProviderLink: c.permalink
      }};
    } else if (entry.Brand === brands.cy && entry.Contents) {
      var k = Object.keys(entry.Contents);
      if (k && k.length > 0) {
        var v = entry.Contents[k[0]];
        if (v) {
          return {ContentsFormat: formats.table, Type: entryTypes.note, Contents: {
            Status: v.status, Code: v.statuscode, Score: v.generalscore, Classifiers: JSON.stringify(v.classifiers), ConfirmCode: v.confirmcode, Error: v.error, Provider: providers.cy
          }};
        }
      }
    } else if (entry.Brand === brands.wf && entry.Contents && entry.Contents.wildfire && entry.Contents.wildfire.file_info) {
      var c = entry.Contents.wildfire.file_info;
      return {ContentsFormat: formats.table, Type: entryTypes.note, Contents: {
        Type: c.filetype, Malware: c.malware, MD5: c.md5, SHA256: c.sha256, Size: c.size, Provider: providers.wf
      }};
    } else if (entry.Brand === brands.cs && c && c.length && c[0].indicator) {
      return shortCrowdStrike(entry);
    } else if (entry.Brand === brands.threatconnect && c && c.data && c.data.file) {
      var file = c.data.file;
      return {ContentsFormat: formats.table, Type: entryTypes.note, Contents: {
        File: file.file, Rating: file.rating, Confidence: file.confidence, Sha256: file.sha256, Sha1: file.sha1, MD5: file.md5,
        DateAdded: file.dateAdded, ID: file.id, webLink: file.webLink, Provider: entry.Brand
      }};
    }
  }
  return entry;
}

/**
 * Formats an ip reputation entry into a short table
 * @deprecated
 * @param {Object} entry - reputation entry
 * @return {Object} the table entry
 */
function shortIP(entry) {
  if (entry.Type !== entryTypes.error && entry.ContentsFormat === formats.json) {
    var c = entry.Contents;
    if (entry.Brand === brands.xfe && entry.Contents) {
      var cr = c.reputation;
      return {ContentsFormat: formats.table, Type: entryTypes.note, Contents: {
        IP: cr.ip, Score: cr.score, Geo: cr.geo && cr.geo['country'] ? cr.geo['country'] : '',
        Categories: cr.cats ? JSON.stringify(cr.cats) : '', Provider: providers.xfe
      }};
    } else if (entry.Brand === brands.vt && entry.Contents) {
      var positives = 0;
      for (var i = 0; i < entry.Contents.detected_urls.length; i++) {
        if (entry.Contents.detected_urls[i].positives > thresholds.vtPositives) {
          positives++;
        }
      }
      return {ContentsFormat: formats.table, Type: entryTypes.note, Contents: {
        DetectedURLs: positives, Provider: providers.vt
      }};
    } else if (entry.Brand === brands.cs && c && c.length && c[0].indicator) {
      return shortCrowdStrike(entry);
    } else if (entry.Brand === brands.threatconnect && c && c.data && c.data.address) {
      var addr = c.data.address;
      return {ContentsFormat: formats.table, Type: entryTypes.note, Contents: {
        IP: addr.ip, Rating: addr.rating, Confidence: addr.confidence,
        DateAdded: addr.dateAdded, ID: addr.id, webLink: addr.webLink, Provider: entry.Brand
      }};
    }
  }
  return entry;
}

/**
 * Formats a domain reputation entry into a short table
 * @deprecated
 * @param {Object} entry - reputation entry
 * @return {Object} the table entry
 */
function shortDomain(entry) {
  if (entry.Type !== entryTypes.error && entry.ContentsFormat === formats.json) {
    if (entry.Brand === brands.vt && entry.Contents) {
      var c = entry.Contents;
      var positives = 0;
      for (var i = 0; i < entry.Contents.detected_urls.length; i++) {
        if (entry.Contents.detected_urls[i].positives > 20) {
          positives++;
        }
      }
      return {ContentsFormat: formats.table, Type: entryTypes.note, Contents: {
        DetectedURLs: positives, Provider: providers.vt
      }};
    }
  }
  return entry;
}

/**
 * Flatten a JSON tree object to key-value format
 * @param {Object} object - The object to be flattened
 * @return {Object} the formatted object (key-value format)
 */
var treeToFlattenObject = function(object) {
    if(typeof object !== 'object' && !(Array.isArray(object))){
        return object;
    }
    var retVal = {};

    for (var i in object) {
        if (!object.hasOwnProperty(i)) continue;
        if ((typeof object[i]) == 'object' && (!Array.isArray(object[i]) || !(object[i].length == 0 || (typeof object[i][0] != 'object')))) {
            var flatObject = treeToFlattenObject(object[i]);
            for (var x in flatObject) {
                if (!flatObject.hasOwnProperty(x)) continue;
                retVal[i + '.' + x] = flatObject[x];
            }
        } else {
            retVal[i] = object[i];
        }
    }
    return retVal;
};


/**
 * Base64 encode utiliy. Use Base64.encode(<value>) to encode a string into base64
 * @return A base64 encoded string
 */
var Base64 = {
      _keyStr: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",
      encode: function(input) {
        var output = "";
        var chr1, chr2, chr3, enc1, enc2, enc3, enc4;
        var i = 0;
        while (i < input.length) {
          chr1 = input.charCodeAt(i++);
          chr2 = input.charCodeAt(i++);
          chr3 = input.charCodeAt(i++);
          enc1 = chr1 >> 2;
          enc2 = ((chr1 & 3) << 4) | (chr2 >> 4);
          enc3 = ((chr2 & 15) << 2) | (chr3 >> 6);
          enc4 = chr3 & 63;
          if (isNaN(chr2)) {
            enc3 = enc4 = 64;
          } else if (isNaN(chr3)) {
            enc4 = 64;
          }
          output = output + this._keyStr.charAt(enc1) + this._keyStr.charAt(enc2) + this._keyStr.charAt(enc3) + this._keyStr.charAt(enc4);
        }

        return output;
      }
};

/**
 * Add the given obj to the path while making sure to append Malicious property
 * @param {Object} context - The current war room context, to which the value should be added
 * @param {String} path - The context path in which the object shoud be added
 * @param {Object} obj - The object to be flattened
 * @return {Undefined} The function does not return a value
 */
function addMalicious(context, path, obj) {
    obj['properties_to_append'] = ['Malicious'];
    context[path] = obj;
}

// Constants for common merge paths
var outputPaths = {
    file: 'File(val.MD5 && val.MD5 === obj.MD5 || val.SHA1 && val.SHA1 === obj.SHA1 || val.SHA256 && val.SHA256 === obj.SHA256)',
    ip: 'IP(val.Address && val.Address === obj.Address)',
    url: 'URL(val.Data && val.Data === obj.Data)',
    domain: 'Domain(val.Name && val.Name === obj.Name)',
    cve: 'CVE(val.ID && val.ID === obj.ID)',
    email: 'Account.Email(val.Address && val.Address === obj.Address)'
};


/**
 * Converts score (in number format) to human readable reputation format
 * @param {Int} score - The score to be formatted
 * @return {String} The formatted score
 */
function scoreToReputation(score) {
    if (score === 3){
        return 'Bad';
    }
    if (score === 2){
        return 'Suspicious';
    }
    if (score === 1){
        return 'Good';
    }
    return 'None';
};

/**
 * Check if the given IP address is in the given subnet
 * @param {String} ip - The IP address
 * @param {String} subnet - The subnet
 * @return {String} True if IP is in the subnet, false otherwise
 */
function isIPInSubnet(ip, subnet) {
    function IPnumber(IPaddress) {
        return IPaddress.split('.').reduce(function(int, oct) {return (int << 8) + parseInt(oct, 10);}, 0) >>> 0;
    }

    function IPmask(maskSize) {
        return -1<<(32-maskSize);
    }

    var parts = subnet.split('/');
    if (parts.length == 1) {
        return ip == parts[0];
    }
    return (IPnumber(ip) & IPmask(parts[1])) === (IPnumber(parts[0]) & IPmask(parts[1]));
}

/**
 * Converts all cells in a JSON form Demisto table to human-readable strings
 * @param {Object} obj - The Demisto table
 * @return {Object} - A new Demisto table containing the same fields as formatted strings
 */
function formatTableValues(obj) {

  /* Helper function to reduces multiples newlines in a string */
  var reduceNewlines = function(str) {
      var res = str;
      while (res.indexOf('\n\n\n') != -1) {
          res = res.replace('\n\n\n', '\n\n');
      }
      return res;
  }

  /* Helper function that handles the padding of new lines by depth */
  var indent = function(depth) {
      var res = ''
      for (var i = 0; i < (depth || 0); i++) {
          res += '  ';
      }
      return res;
  }

  /* Helper function that rucurses an object, formatting it's values as strings */
  var formatTableValuesRecursive = function(obj, depth) {
      var res = '';

      /* Return non objects (or dates) as strings */
      if (!obj || typeof obj !== 'object' || !Object.keys(obj).length) {
            return indent(depth || 0) + obj + '\n';  // this will always convert to string type
      }

      /* Recurse all object keys, formatting values as independent lines, increasing depth with each call */
      Object.keys(obj).forEach(function(key) {
          var value = obj[key];
          var isArrayElement = obj instanceof Array;

          /* Handle object values in a new call */
          if (typeof value === 'object') {
              if (isArrayElement) {
                  res += formatTableValuesRecursive(value, (depth || 0)) + '\n';
              } else {
                  res += indent(depth) + key + '\n';
                  res += formatTableValuesRecursive(value, (depth || 0) + 1) + '\n';
              }
          } else {
              /* Format primitives as a string */
              var keyStr = (isArrayElement) ? (parseInt(key) + 1) : key;    // 1-based indexing for arrays for better readability
              res += indent(depth) + keyStr + ': ' + value + '\n';
          }
      });

      res = reduceNewlines(res);
      return res;
  }

  /* Run all object keys and invoke the recursive helper function */
  if (!obj || typeof obj !== 'object' || !Object.keys(obj).length) {
      return obj;
  }
  var res = {};
  Object.keys(obj).forEach(function(key) {
      var str = formatTableValuesRecursive(obj[key]);
      str = str.trim('\n');   //There's no need for a newline at the end of the entire stirng
      res[key] = str;
  });

  return res;
}

/********************************** Date Formatting **************************************/
/* Date formats
  %d - day 01, 02 ... 31
  %m - month 01, 02 .. 12
  %y - 95, 17
  %Y - year 1995, 2017
  %H - hour 01, 02 .. 24
  %M - minute 01, 02 .. 60
  %S - seconds 01, 02 .. 60
  %f - millisecond 001, 002, 003 ... 999
  %z - timezone (empty), +0000, -0400, +1030
  %Z - timezone (empty), UTC, EST, CST
*/
var month_names_short = {
    'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun':6, 'Jul':7, 'Aug':8, 'Sep':9, 'Oct':10, 'Nov':11, 'Dec':12
};

/**
 * Formats a date object to a string according to the given format.
 * @deprecated
 * @param {Date} date - The date object to be formatted
 * @param {Date} format - The format string. Should be a legal python datetime format (e.g. "%d %Y %H:%M:%S")
 * @return {string} A string representation of date object according to format
 */
function dateToString(date, format) {
    if (!date || !(date instanceof Date) || typeof date.getMonth !== 'function' || String(date.getDate()) === 'NaN') {
        throw date + ' must be of type Date';
    }

    var dateString = format;
    if (format.indexOf('%d') > -1) {
        if (Number(date.getDate()) < 10) {
            dateString = dateString.replace('%d', '0' + date.getDate());
        } else {
            dateString = dateString.replace('%d', date.getDate());
        }
    }
    if (format.indexOf('%m') > -1) {
        if (Number(date.getMonth()) + 1 < 10) {
            dateString = dateString.replace('%m', '0' + (date.getMonth() + 1));
        } else {
            dateString = dateString.replace('%m', date.getMonth() + 1);
        }
    }
    if (format.indexOf('%y') > -1) {
        if (Number(date.getYear()) < 10) {
            dateString = dateString.replace('%y', '0' + date.getYear());
        } else {
            dateString = dateString.replace('%y', date.getYear());
        }
    }
    if (format.indexOf('%Y') > -1) {
        dateString = dateString.replace('%Y', date.getFullYear());
    }
    if (format.indexOf('%H') > -1) {
        if (date.getHours() < 10) {
            dateString = dateString.replace('%H', '0' + date.getHours());
        } else {
            dateString = dateString.replace('%H', date.getHours());
        }
    }
    if (format.indexOf('%M') > -1) {
        if (date.getMinutes() < 10) {
            dateString = dateString.replace('%M', '0' + date.getMinutes());
        } else {
            dateString = dateString.replace('%M', date.getMinutes());
        }
    }
    if (format.indexOf('%S') > -1) {
        if (date.getSeconds() < 10) {
            dateString = dateString.replace('%S', '0' + date.getSeconds());
        } else {
            dateString = dateString.replace('%S', date.getSeconds());
        }
    }
    if (format.indexOf('%f') > -1) {
        if (date.getMilliseconds() < 10) {
            dateString = dateString.replace('%f', '00' + date.getMilliseconds());
        } else if (date.getMilliseconds() < 100) {
            dateString = dateString.replace('%f', '0' + date.getMilliseconds());
        } else {
            dateString = dateString.replace('%f', date.getMilliseconds());
        }
    }

    return dateString;
}

/**
 * Parses date string to date object.
 * @deprecated
 * @param {string} dateString - date as string
 * @param {string} format - the dateString must fit the format.
 * format is according to date format of python datetime library
 * @return {Date} parsed date object
 */
function stringToDate(dateString, format) {
    if (typeof dateString !== 'string') {
        throw dateString  + ' must be string';
    } else if (typeof format !== 'string') {
        throw format + ' must be string';
    }

    var newDate = new Date(1970, 0, 1, 0, 0, 0, 0);
    var newString = dateString;
    var delta = 0;
    for(var i = 0; i < format.length - 1; i++) {
        switch (format.charAt(i) + format.charAt(i + 1)) {
            case '%d':
                var d = newString.substring(delta + i, delta + i + 2);
                newDate.setDate(Number(d));
                break;
            case '%m':
                var m = newString.substring(delta + i, delta + i + 2);
                newDate.setMonth(Number(m) - 1);
                break;
            case '%b':
                var b = newString.substring(delta + i, delta + i + 3);
                var month = month_names_short[b];
                newDate.setMonth(month - 1);
                delta += 1;
                break;
            case '%y':
                var y = newString.substring(delta + i, delta + i + 2);
                newDate.setYear('20' + y);
                break;
            case '%Y':
                var Y = newString.substring(delta + i, delta + i + 4);
                newDate.setFullYear(Y);
                delta += 2;
                break;
            case '%H':
                var H = newString.substring(delta + i, delta + i + 2);
                newDate.setHours(H);
                break;
            case '%M':
                var M = newString.substring(delta + i, delta + i + 2);
                newDate.setMinutes(M);
                break;
            case '%S':
                var S = newString.substring(delta + i, delta + i + 2);
                newDate.setSeconds(S);
                break;
            case '%f':
                var f = newString.substring(delta + i, delta + i + 3);
                newDate.setMilliseconds(f);
                delta += 1;
                break;
        }
    }

    return newDate;
}

/********************************** Date Formatting end **************************************/

/********************************** HMAC_SHA256 **************************************/

    /* string_to_array: convert a string to a character (byte) array */
    function string_to_array(str) {
      var len = str.length;
      var res = new Array(len);
      for(var i = 0; i < len; i++)
        res[i] = str.charCodeAt(i);
      return res;
    }

    /* array_to_hex_string: convert a byte array to a hexadecimal string */
    function array_to_hex_string(ary) {
      var res = "";
      for(var i = 0; i < ary.length; i++)
        res += SHA256_hexchars[ary[i] >> 4] + SHA256_hexchars[ary[i] & 0x0f];
      return res;
    }


    /* The following are the SHA256 routines */

    /*
       SHA256_init: initialize the internal state of the hash function. Call this
       function before calling the SHA256_write function.
    */

    function SHA256_init() {
      SHA256_H = new Array(0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19);
      SHA256_buf = new Array();
      SHA256_len = 0;
    }

    /*
       SHA256_write: add a message fragment to the hash function's internal state.
       'msg' may be given as string or as byte array and may have arbitrary length.

    */

    function SHA256_write(msg) {
      if (typeof(msg) == "string")
        SHA256_buf = SHA256_buf.concat(string_to_array(msg));
      else
        SHA256_buf = SHA256_buf.concat(msg);
      for(var i = 0; i + 64 <= SHA256_buf.length; i += 64)
        SHA256_Hash_Byte_Block(SHA256_H, SHA256_buf.slice(i, i + 64));
      SHA256_buf = SHA256_buf.slice(i);
      SHA256_len += msg.length;
    }

    /*
       SHA256_finalize: finalize the hash value calculation. Call this function
       after the last call to SHA256_write. An array of 32 bytes (= 256 bits)
       is returned.
    */

    function SHA256_finalize() {
      SHA256_buf[SHA256_buf.length] = 0x80;

      if (SHA256_buf.length > 64 - 8) {
        for(var i = SHA256_buf.length; i < 64; i++)
          SHA256_buf[i] = 0;
        SHA256_Hash_Byte_Block(SHA256_H, SHA256_buf);
        SHA256_buf.length = 0;
      }

      for(var i = SHA256_buf.length; i < 64 - 5; i++)
        SHA256_buf[i] = 0;
        SHA256_buf[59] = (SHA256_len >>> 29) & 0xff;
        SHA256_buf[60] = (SHA256_len >>> 21) & 0xff;
        SHA256_buf[61] = (SHA256_len >>> 13) & 0xff;
        SHA256_buf[62] = (SHA256_len >>> 5) & 0xff;
        SHA256_buf[63] = (SHA256_len << 3) & 0xff;
        SHA256_Hash_Byte_Block(SHA256_H, SHA256_buf);
        var res = new Array(32);

        for(var i = 0; i < 8; i++) {
            res[4 * i + 0] = SHA256_H[i] >>> 24;
            res[4 * i + 1] = (SHA256_H[i] >> 16) & 0xff;
            res[4 * i + 2] = (SHA256_H[i] >> 8) & 0xff;
            res[4 * i + 3] = SHA256_H[i] & 0xff;
        }

        SHA256_H = undefined;
        SHA256_buf = undefined;
        SHA256_len = undefined;
        return res;
    }

    /*
       SHA256_hash: calculate the hash value of the string or byte array 'msg'
       and return it as hexadecimal string. This shortcut function may be more
       convenient than calling SHA256_init, SHA256_write, SHA256_finalize
       and array_to_hex_string explicitly.
    */

    function SHA256_hash(msg) {
      var res;
      SHA256_init();
      SHA256_write(msg);
      res = SHA256_finalize();
      return array_to_hex_string(res);
    }

    /* The following are the HMAC-SHA256 routines */

    /*
       HMAC_SHA256_init: initialize the MAC's internal state. The MAC key 'key'
       may be given as string or as byte array and may have arbitrary length.
    */

    function HMAC_SHA256_init(key) {
      if (typeof(key) == "string")
        HMAC_SHA256_key = string_to_array(key);
      else
        HMAC_SHA256_key = new Array().concat(key);

      if (HMAC_SHA256_key.length > 64) {
        SHA256_init();
        SHA256_write(HMAC_SHA256_key);
        HMAC_SHA256_key = SHA256_finalize();
      }

      for(var i = HMAC_SHA256_key.length; i < 64; i++)
        HMAC_SHA256_key[i] = 0;
      for(var i = 0; i < 64; i++)
        HMAC_SHA256_key[i] ^=  0x36;
      SHA256_init();
      SHA256_write(HMAC_SHA256_key);
    }

    /*
       HMAC_SHA256_write: process a message fragment. 'msg' may be given as
       string or as byte array and may have arbitrary length.
    */

    function HMAC_SHA256_write(msg) {
      SHA256_write(msg);
    }

    /*
       HMAC_SHA256_finalize: finalize the HMAC calculation. An array of 32 bytes
       (= 256 bits) is returned.
    */

    function HMAC_SHA256_finalize() {
      var md = SHA256_finalize();
      for(var i = 0; i < 64; i++)
        HMAC_SHA256_key[i] ^= 0x36 ^ 0x5c;
      SHA256_init();
      SHA256_write(HMAC_SHA256_key);
      SHA256_write(md);
      for(var i = 0; i < 64; i++)
        HMAC_SHA256_key[i] = 0;
      HMAC_SHA256_key = undefined;
      return SHA256_finalize();
    }

    /*
       HMAC_SHA256_MAC: calculate the HMAC value of message 'msg' under key 'key'
       (both may be of type string or byte array); return the MAC as hexadecimal
       string. This shortcut function may be more convenient than calling
       HMAC_SHA256_init, HMAC_SHA256_write, HMAC_SHA256_finalize and
       array_to_hex_string explicitly.
    */

    function HMAC_SHA256_MAC(key, msg) {
      var res;
      HMAC_SHA256_init(key);
      HMAC_SHA256_write(msg);
      res = HMAC_SHA256_finalize();
      return array_to_hex_string(res);
    }

    /* The following lookup tables and functions are for internal use only! */

    SHA256_hexchars = new Array('0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
      'a', 'b', 'c', 'd', 'e', 'f');

    SHA256_K = new Array(
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
      0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
      0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
      0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
      0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
      0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
      0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
      0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    );

    function SHA256_sigma0(x) {
      return ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
    }

    function SHA256_sigma1(x) {
      return ((x >>> 17) | (x << 15)) ^ ((x >>> 19) | (x << 13)) ^ (x >>> 10);
    }

    function SHA256_Sigma0(x) {
      return ((x >>> 2) | (x << 30)) ^ ((x >>> 13) | (x << 19)) ^
        ((x >>> 22) | (x << 10));
    }

    function SHA256_Sigma1(x) {
      return ((x >>> 6) | (x << 26)) ^ ((x >>> 11) | (x << 21)) ^
        ((x >>> 25) | (x << 7));
    }

    function SHA256_Ch(x, y, z) {
      return z ^ (x & (y ^ z));
    }

    function SHA256_Maj(x, y, z) {
      return (x & y) ^ (z & (x ^ y));
    }

    function SHA256_Hash_Word_Block(H, W) {
      for(var i = 16; i < 64; i++)
        W[i] = (SHA256_sigma1(W[i - 2]) +  W[i - 7] +
          SHA256_sigma0(W[i - 15]) + W[i - 16]) & 0xffffffff;
      var state = new Array().concat(H);
      for(var i = 0; i < 64; i++) {
        var T1 = state[7] + SHA256_Sigma1(state[4]) +
          SHA256_Ch(state[4], state[5], state[6]) + SHA256_K[i] + W[i];
        var T2 = SHA256_Sigma0(state[0]) + SHA256_Maj(state[0], state[1], state[2]);
        state.pop();
        state.unshift((T1 + T2) & 0xffffffff);
        state[4] = (state[4] + T1) & 0xffffffff;
      }
      for(var i = 0; i < 8; i++)
        H[i] = (H[i] + state[i]) & 0xffffffff;
    }

    function SHA256_Hash_Byte_Block(H, w) {
      var W = new Array(16);
      for(var i = 0; i < 16; i++)
        W[i] = w[4 * i + 0] << 24 | w[4 * i + 1] << 16 |
          w[4 * i + 2] << 8 | w[4 * i + 3];
      SHA256_Hash_Word_Block(H, W);
    }

    /**************************** HMAC_SHA256 end *******************************/

  /**************************** REGEX FORMATTING *******************************/

    var ipRegex = /\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b/;
    var emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/;
    var hashRegex = /[a-fA-F0-9]/;
    var md5Regex = /\b[a-fA-F\d]{32}\b/gm;
    var sha1Regex = /\b[a-fA-F\d]{40}\b/gm;
    var sha256Regex = /\b[a-fA-F\d]{64}\b/gm;

  /**************************** REGEX FORMATTING end *******************************/

function getDemistoVersion() {
    try {
        return demistoVersion();
    } catch (ex) {
        throw 'Failed retriving server version - ' + ex;
    }
}
function isDemistoVersionGE(version, buildNumber) {
    var serverVersion = {};
    try {
        serverVersion = getDemistoVersion();
        if (serverVersion.version > version) {
            return true;
        } else if (serverVersion.version === version) {
            if (buildNumber) {
                var intBuildNumber = parseInt(serverVersion.buildNumber);
                if (isNaN(intBuildNumber)) {
                    // dev editions are not comparable
                    logDebug('isDemistoVersionGE: Error. Input: version: [{0}] buildNumber: [{1}]. server version: {2}'.format(version, buildNumber, JSON.stringify(serverVersion)));
                    return true;
                }
                return (intBuildNumber >= parseInt(buildNumber));
            }
            return true;
        } else {
            return false;
        }
    } catch (ex) {
        if (ex instanceof ReferenceError) {
            // demistoVersion was added in 5.0.0. We are currently running in 4.5.0 and below
            if (serverVersion >= '5.0.0') {
                return false;
            }
        }
        throw ex;
    }
}
function getVersionedIntegrationContext(sync, withVersion) {
    if (sync === undefined) {
        sync = true;
    }
    if (withVersion === undefined) {
        withVersion = false;
    }
    if (isDemistoVersionGE('6.2.0')) {
        var integrationContext = getIntegrationContext(sync);
        if (!sync || withVersion) {
            return integrationContext;
        } else {
            return integrationContext.context;
        }
    } else {
        return getIntegrationContext();
    }
}
function setVersionedIntegrationContext(context, sync, version) {
    if (sync === undefined) {
        sync = true;
    }
    if (version === undefined) {
        version = -1;
    }
    if (isDemistoVersionGE('6.2.0')) {
        return setIntegrationContext(context, version, sync);
    } else {
        return setIntegrationContext(context);
    }
}
/* version should be given if theres a known version we must update according to.
In case of a known version, retries should be set to 0 */
function mergeVersionedIntegrationContext({newContext, retries = 0,version, objectKey = {}}) {
    var savedSuccessfully = false;
    do {
        logDebug("mergeVersionedIntegrationContext - retries: " + retries  + " given version: " + version)

        var versionedIntegrationContext = getVersionedIntegrationContext(true, true) || {};
        var context = versionedIntegrationContext.context;
        mergeContexts(newContext, context, objectKey);
        var response = setVersionedIntegrationContext(context, true, version || versionedIntegrationContext.version);
        if(response.Error){
            logDebug(response.Error)
        }
        else
        {
            savedSuccessfully = true;
        }

    } while (!savedSuccessfully && retries-- > 0);
    if(!savedSuccessfully){
        throw 'Did not merge context successfully.'
    }
}
/*
    This function will mutate existingContext, updating it according to newContext.
*/


function mergeContexts(newContext, existingContext, objectKeys = {}) {
    for (var key in newContext) {
        existingContext[key] = existingContext[key] && objectKeys[key] ?
            mergeContextLists(newContext[key], existingContext[key], objectKeys[key])
            : existingContext[key] = newContext[key];
    }
}

function mergeContextLists(newItems, oldItems, objectKey) {
    let toMapByKey = (prev, curr) => {
        prev[curr[objectKey]] = curr;
        return prev;
    };

    oldItemsByKey = oldItems.reduce(toMapByKey, {});
    newItemsByKey = newItems.reduce(toMapByKey, {});
    return Object.values(Object.assign(oldItemsByKey, newItemsByKey)).filter(e => !e['remove']);
}
