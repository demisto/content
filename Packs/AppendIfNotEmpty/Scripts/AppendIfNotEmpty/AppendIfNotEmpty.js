function toBoolean(value) {
    if (typeof(value) === 'string') {
        if (['yes', 'true'].indexOf(value.toLowerCase()) != -1) {
            return true;
        } else if (['no', 'false'].indexOf(value.toLowerCase()) != -1) {
            return false;
        }
        throw 'Argument does not contain a valid boolean-like value';
    }
    return value ? true : false;
}

function toArray(value, raw) {
    if (!value) {
        return [];
    } else if (Array.isArray(value)) {
        return value;
    } else if (raw && typeof(value) === 'string') {
        return argToList(value);
    } else {
        return [value];
    }
}

if (!args.item) {
    return args.value;
}
var vals1 = toArray(args.value, true);
var vals2 = toArray(args.item, toBoolean(args.raw));
return vals1.concat(vals2);
