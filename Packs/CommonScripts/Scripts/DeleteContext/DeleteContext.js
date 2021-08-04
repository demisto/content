function errorEntry(text) {
    return  {
        ContentsFormat: formats.text,
        Type: entryTypes.error,
        Contents: text
    };
}

var fieldsToDelete;
var shouldDeleteAll = (args.all === 'yes');
var isSubPlaybookKey = (args.subplaybook === 'yes');
if (args.subplaybook === 'auto') {
    var res = executeCommand('Print', { value: 'id=${currentPlaybookID}' });
    if (res && res[0].Contents && res[0].Contents.startsWith('id=')) {
       var idArr = res[0].Contents.split('=');
       if (idArr.length === 2 && idArr[1]) {
           isSubPlaybookKey = true;
       }
    }
}
if (!shouldDeleteAll && !args.key) {
    return {Contents: 'You must specify key or all=yes',
                    ContentsFormat: formats.text,
                    Type: entryTypes.error};
}
function hasDuplicates(arr) {
    return arr.some( function(item) {
        return arr.indexOf(item) !== arr.lastIndexOf(item);
    });
}
if (shouldDeleteAll) {
    var keysToKeep = (args.keysToKeep) ? args.keysToKeep.split(',').map(function(item) { return item.trim(); }) : [];
    var keysToKeepObj = {};
    var KeepDBotScoreKey = false;
    index = keysToKeep.indexOf("DBotScore");
    if (index > -1) {
      keysToKeep.splice(index, 1);
      KeepDBotScoreKey = true;
    }
    var value;
    for (var i = 0; i < keysToKeep.length; i++) {
        value = dq(invContext, keysToKeep[i]);
        if (value) {
            if (Array.isArray(value) && hasDuplicates(value)) {
                setContext(keysToKeep[i], value);
                continue;
            }
            keysToKeepObj[keysToKeep[i]] = value;
        }
    }
    fieldsToDelete = Object.keys(invContext);

    // delete each field in context
    var errorsStr = "";
    for (var i = 0; i < fieldsToDelete.length; i++) {
        var key = fieldsToDelete[i];
        if (isSubPlaybookKey) {
            key = 'subplaybook-${currentPlaybookID}.' + key;
        }
        if (key !== "DBotScore" || !KeepDBotScoreKey) {
            var result = executeCommand('delContext', {key: key});
            if(!result || result.type === entryTypes.error) {
                errorsStr = errorsStr + "\n" + result.Contents;
            }
        }
    }
    var message;
    if (errorsStr) {
        message = "Context cleared with the following errors:" + errorsStr;
    } else {
        message = "Context cleared";
    }
    return {
        Type: entryTypes.note,
        Contents: message,
        ContentsFormat: formats.json,
        HumanReadable: message,
        ReadableContentsFormat: formats.markdown,
        EntryContext: keysToKeepObj
    };
} else if (args.index !== undefined) {
    // delete key in a specific index
    var index = parseInt(args.index);
    if (isNaN(index)) {
        return errorEntry("Invalid index " + args.index)
    }
    var contextVal = invContext[args.key];
    if (!contextVal) {
        return "Key [" + args.key + "] was not found.";
    }
    if (!Array.isArray(contextVal)) {
        contextVal = [contextVal];
    }

    if (index < 0 || index >= contextVal.length) {
        return errorEntry("Index out of range " + args.index)
    }

    // splice is not supported currently
    var newArr = [];
    for (var i = 0; i < contextVal.length; i++) {
        if (i !== index) {
            newArr.push(contextVal[i])
        }
    }

    if (newArr.length === 0) {
        var key = args.key;
        if (isSubPlaybookKey) {
          key = 'subplaybook-${currentPlaybookID}.' + key;
        }
        executeCommand('delContext', { key: key });
    } else {
        setContext(args.key, newArr);
    }

    return "Successfully deleted index " + index + " from key " + args.key;
} else {
    var key = args.key;
    if (isSubPlaybookKey) {
      key = 'subplaybook-${currentPlaybookID}.' + key;
    }
    return executeCommand('delContext', {key: key});
}
