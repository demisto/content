function valueToValidString(value) {
    if (typeof value === 'number' || typeof value === 'boolean' ) {
        value = value.toString();
    }
    else if (typeof value === 'object') {
        value = JSON.stringify(value);
    }
    value = value.trim().replace(/\n/g, '\\n').replace(/"/g, '""');
    if (value && value.indexOf(',') > -1) {
        value = '"' + value + '"';
    }
    return value;
}

function extractHeaders(objArray) {
    var headersInOrder = [];
    var headers = {};
    for(var i = 0; i < objArray.length; i++){
        var objHeaders = Object.keys(objArray[i]);
        for(var j = 0; j < objHeaders.length; j++){
            header = objHeaders[j];
            if (!headers.hasOwnProperty(objHeaders[j])) {
                headersInOrder.push(objHeaders[j]);
                // maintain a map to enable quick check if the header was added before
                headers[header] = '';
            }
        }
    }

    return headersInOrder;
}

function convertToCSV(objArray, headers) {
    // if objArray is an array of strings then return a single line of values
    if (typeof objArray[0] !== 'object') {
        // add headrs line
        if (headers && headers.length >= objArray.length){
            headers = headers.slice(0, objArray.length);
            return headers.join() + '\n' + objArray.join();
        }
        return objArray.join();
    }
    // create file headers
    if (!headers) {
        headers = extractHeaders(objArray);
    }
    // collect values into rows
    var rows = [];

    for(var i = 0; i < objArray.length; i++){
        obj = objArray[i];
        if (typeof obj !== 'object') {
            throw "Array contains '" + typeof obj + "' member: '" + obj + "'" ;
        }
        var row = [];
        // loop on headersInOrder to extract values from the object and add to 'row' to match headers order.
        for(var j = 0; j < headers.length; j++){
            header = headers[j];
            var value = '';
            if (obj.hasOwnProperty(header)) {
                value = valueToValidString(obj[header]);
            }
            row.push(value);
        }
        rows.push(row);
    }

    // create file content
    var fileContent = headers.join();
    for (var i = 0; i < rows.length;  i++) {
        var line = rows[i].join();
        fileContent += '\n' + line ;
    }
    return fileContent;
}

// string was passed as input
if (typeof args.csvArray === 'string') {
    // add array brackets if missing from string
    args.csvArray = args.csvArray[0] == '[' ? args.csvArray : '[' + args.csvArray + ']'
    // try to parse string to json
    try {
        args.csvArray = JSON.parse(args.csvArray);
    } catch (err) {
        return {
            Type: entryTypes.error,
            ContentFormat: formats.text,
            Contents: 'The csvArray that was passed was not array!'
        };
    }
}
// json object passed as input
if (!Array.isArray(args.csvArray)) {
    //wrap in an array
    args.csvArray = [args.csvArray];
}
if (args.headers && !Array.isArray(args.headers)){
    args.headers = args.headers.split(',');
}

var csvString = convertToCSV(args.csvArray, args.headers);
if (args.codec === 'UTF-16-BOM') {
    var utf16Bom = '\uFEFF';
    csvString = utf16Bom + csvString;
}
var createdFileID = saveFile(csvString);

return {
    Type: 3,
    FileID: createdFileID,
    File: args.fileName,
    Contents: args.fileName
};
