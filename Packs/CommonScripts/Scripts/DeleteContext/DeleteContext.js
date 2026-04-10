LINE_SEPARATOR = '\n';

function errorEntry(text) {
    return  {
        ContentsFormat: formats.text,
        Type: entryTypes.error,
        Contents: text
    };
}

/**
 * Deletes keys from the context and handles errors.
 * @param {Array<string>} keysToDelete - An array of keys to delete.
 * @param {Array<string>} _keysToKeep - An array of keys to keep.
 * @returns {string} A message summarizing the outcome of the delete operation.
 */
function deleteKeys(keysToDelete = [], _keysToKeep = [], keepDBotScoreKey = false) {
    var deletedKeys = []
    var errors = []
    var message = '';
    for (var key of keysToDelete) {
        if (key == DBOT_SCORE_KEY && keepDBotScoreKey){
            continue;
        }
        const originalKey = typeof key === "string" ? key.trim() : key;
        const keyToDelete = isSubPlaybookKey ? 'subplaybook-${currentPlaybookID}.' + originalKey: originalKey;
        const result = executeCommand('delContext', { key: keyToDelete });
        if (!result || result.type === entryTypes.error ) {
            errors.push(result.Contents);
        } else {
            // Do not state deletion of _keysToKeep since they are re-created.
            if (_keysToKeep.indexOf(keyToDelete) === -1) {
                deletedKeys.push(key);
            }
        }
    }
    if (deletedKeys.length > 0) {
        message += LINE_SEPARATOR + `Successfully deleted keys '${deletedKeys.join("', '")}' from context.`;
    }
    return errors.join(LINE_SEPARATOR) + LINE_SEPARATOR + message;
}

const DBOT_SCORE_KEY = 'DBotScore';
var shouldDeleteAll = (args.all === 'yes');
var isSubPlaybookKey = (args.subplaybook === 'yes');
var keysToKeep = (args.keysToKeep) ? args.keysToKeep.split(',').map(item => item.trim()) : [];
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
    var keysToKeepObj = {};
    var keepDBotScoreKey = false;
    var value;
    
    index = keysToKeep.indexOf("DBotScore");
    if (index > -1) {
        keysToKeep.splice(index, 1);
        keepDBotScoreKey = true;
    }
    
    // Collect all the keys to keep.
    for (var i = 0; i < keysToKeep.length; i++) {
        value = dq(invContext, keysToKeep[i]);
        if (value !== null && value !== undefined) {
            // in case the original path has a reference to a list indexing of the form "root.[0].path" or "root.[1]" remove it.
            new_context_path = keysToKeep[i].replace(/\.\[\d+\]/g, '');

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
    // Delete all the keys, do not state deletion of keysToKeep since they are re-created.
    var message = deleteKeys(keysToDelete, keysToKeep, keepDBotScoreKey);

    return {
        Type: entryTypes.note,
        Contents: message,
        ContentsFormat: formats.text,
        HumanReadable: message,
        ReadableContentsFormat: formats.markdown,
        // Re-create keysToKeep with collected object.
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
    var keysToDelete = (typeof args.key === "string") ? args.key.split(',') : [args.key]
    var message = deleteKeys(keysToDelete)
    return {
        Type: entryTypes.note,
        Contents: message,
        ContentsFormat: formats.text,
        HumanReadable: message,
        ReadableContentsFormat: formats.markdown,
        EntryContext: keysToKeepObj
    };
}
