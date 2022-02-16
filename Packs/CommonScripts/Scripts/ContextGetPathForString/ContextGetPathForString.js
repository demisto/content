var path = args.path
var str = args.str;
var flat = {};

function searchString(obj) {
    flattenFields(obj,undefined,flat);
    keysArr = Object.keys(flat);
    for (i = 0; i < keysArr.length; i++) {
        if (flat[keysArr[i]] === str) {
            return keysArr[i]
        }
    }
    return null;
}

if (!path) {
    return searchString(invContext);
}

var contextObject = dq(invContext, path);

if (!contextObject) {
    throw 'Path ' + path + ' is not in the context.';
}

return searchString(contextObject);


