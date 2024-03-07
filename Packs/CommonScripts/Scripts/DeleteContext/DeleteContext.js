function errorEntry(text) {
    return  {
        ContentsFormat: formats.text,
        Type: entryTypes.error,
        Contents: text
    };
}

function hasDuplicates(arr) {
    return arr.some( function(item) {
        return arr.indexOf(item) !== arr.lastIndexOf(item);
    });
}

/**
 * Checks if a nested key path exists within an object.
 * 
 * This function takes a context object and a string representing a nested key path (e.g., 'key1.innerkey.innerinnerkey').
 * It then recursively checks whether the full path specified by the key exists within the context object.
 *
 * @param {Object} context The nested object to search within.
 * @param {string} key The nested key path, with each level separated by '.' (e.g., 'key1.innerkey2.innerinnerkey3').
 * @returns {boolean} Returns true if the key exists in the object, false otherwise.
 */
function keyExists(context, key) {
    const keys = key.split('.'); 
    let currentContext = context;

    for (let i = 0; i < keys.length; i++) {
        if (!(keys[i] in currentContext)) {
            return false;
        }
        // Move deeper into the context for the next iteration.
        currentContext = currentContext[keys[i]];
    }
    return true;
}

/**
 * Deletes keys from the context and handles errors.
 * @param {Array<string>} keys - An array of keys to delete.
 * @returns {string} A message summarizing the outcome of the delete operation.
 */
function deleteKeys(keys, isSubPlaybookKey) {
    let deletedKeys = [];
    let errorsStr = "";
    for (let key of keys) {
        key = key.trim();
        if (isSubPlaybookKey) {
            key = `subplaybook-${currentPlaybookID}.${key}`;
        }

        if (keyExists(invContext, key)) {
            var result = executeCommand('delContext', { key: key });
            if (!result || result.type === entryTypes.error) {
                errorsStr += `\n${result.Contents}`;
            } else {
                deletedKeys.push(key);
            }
        } else {
            errorsStr += `\nKey '${key}' does not exist.`;
        }
    }

    let message = '';
    if (errorsStr) {
        message += "Encountered errors deleting keys: " + errorsStr;
    }
    if (deletedKeys.length > 0) {
        message += `\nSuccessfully deleted keys '${deletedKeys.join("', '")}' from context.`;
    }

    return message;
}

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

if (shouldDeleteAll) {
    var keysToKeep = (args.keysToKeep) ? args.keysToKeep.split(',').map(item => item.trim()) : [];
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
        if (value !== null && value !== undefined) {
            // in case the original path has a reference to a list indexing of the form "root.[0].path" or "root.[1]" remove it.
            new_context_path = keysToKeep[i].replace(/\.\[\d+\]/g, '');

            if (Array.isArray(value) && hasDuplicates(value)) {
                setContext(new_context_path, value);
                continue;
            }
            // in case user asks to keep the same key in different array elements, for example: Key.[0].Name,Key.[1].Name
            if (new_context_path in keysToKeepObj) {
                if (!Array.isArray(keysToKeepObj[new_context_path])) {
                    keysToKeepObj[new_context_path] = [keysToKeepObj[new_context_path]];
                }
                keysToKeepObj[new_context_path].push(value);
            } else {
                keysToKeepObj[new_context_path] = value;
            }
        }
    }
    var keysToDelete = Object.keys(invContext);

    var message = deleteKeys(keysToDelete, isSubPlaybookKey)

    return {
        Type: entryTypes.note,
        Contents: message,
        ContentsFormat: formats.json,
        HumanReadable: message,
        ReadableContentsFormat: formats.markdown,
        EntryContext: keysToKeepObj
    };

} else if (args.index !== undefined) {
    // Delete key in a specific index.
    var index = parseInt(args.index);
    if (isNaN(index)) {
        return errorEntry("Invalid index " + args.index)
    }
    var contextVal = dq(invContext, args.key);
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
    // Supporting comma separated list of keys to be deleted.
    var keysToDelete = args.key.split(',')
    var deletedKeys = []
    var errorsStr = "";
    for (let key of keysToDelete){
        key = key.trim()
        if (isSubPlaybookKey) {
            key = 'subplaybook-${currentPlaybookID}.' + key;
        }

        if (keyExists(invContext, key)){
            var result = executeCommand('delContext', {key: key});
            if (!result || result.type === entryTypes.error) {
                errorsStr +=`\n${result.Contents}`
            } else {
                deletedKeys.push(key)
            }
        } else {
            errorsStr += `\nKey '${key}' does not exist.`
        }
    }

    var message = deleteKeys(keysToDelete, isSubPlaybookKey)
    return {
        Type: entryTypes.note,
        Contents: message,
        ContentsFormat: formats.json,
        HumanReadable: message,
        ReadableContentsFormat: formats.markdown,
        EntryContext: keysToKeepObj
    };

}
