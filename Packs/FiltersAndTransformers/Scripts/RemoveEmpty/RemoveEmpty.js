const EMPTY_TOKENS = argToList(args.empty_values);

function isObject(o) {
    return o instanceof Object && !(o instanceof Array);
}

function isEmpty(v) {
    return (v === undefined) ||
           (v === null) ||
           (typeof(v) == 'string' && (!v || EMPTY_TOKENS.indexOf(v) !== -1)) ||
           (Array.isArray(v) && v.filter(x => !isEmpty(x)).length === 0) ||
           (isObject(v) && Object.keys(v).length === 0);
}

function removeEmptyProperties(obj) {
    Object.keys(obj).forEach(k => {
        var ov = obj[k];
        if (isObject(ov)) {
            removeEmptyProperties(ov);
        } else if (Array.isArray(ov)) {
            ov.forEach(av => isObject(av) && removeEmptyProperties(av));
            obj[k] = ov.filter(x => !isEmpty(x));
        }
        if (isEmpty(ov)) {
            delete obj[k];
        }
    });
}

var vals = Array.isArray(args.value) ? args.value : [args.value];

if (toBoolean(args.remove_keys)) {
    vals.forEach(v => isObject(v) && removeEmptyProperties(v));
}
return vals.filter(x => !isEmpty(x));
