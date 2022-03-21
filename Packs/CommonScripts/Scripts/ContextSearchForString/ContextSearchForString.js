var path = args.path;
var str = args.str;
var flat={};

function searchString(obj) {
    flattenFields(obj,undefined,flat);
    keysArr = Object.keys(flat);
    for (i = 0; i < keysArr.length - 1; i++) {
        if (flat[keysArr[i]] === str) {
            return true;
        }
    }
    return false;
}

if (!path) {
    return searchString(invContext);
}

var contextObject = dq(invContext, path);

if (!contextObject) {
    throw 'Path ' + path + ' is not in the context.';
}

return searchString(contextObject);


