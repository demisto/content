function toBoolean(value) {
    if (typeof (value) === 'string') {
        if (['yes', 'true'].indexOf(value.toLowerCase()) != -1) {
            return true;
        } else if (['no', 'false'].indexOf(value.toLowerCase()) != -1) {
            return false;
        }
        throw 'Argument does not contain a valid boolean-like value';
    }
    return value ? true : false;
}

function isValueEmpty(value) {
    if (Array.isArray(value) && value.length === 1) {
        value = value[0];
    }

    const valueIsStringNull = typeof value === 'string' && (value.toLowerCase() === 'none' || value.toLowerCase() === 'null' || value === '');

    return value === null || (Array.isArray(value) && value.length === 0) || (value.constructor == Object && Object.keys(value).length === 0) || valueIsStringNull;
}


function getValueToSet(value) {
    const applyIfEmpty = toBoolean(args.applyIfEmpty);

    if (value == null || (applyIfEmpty && isValueEmpty(value))) {
        value = args.defaultValue;
    }

    if (value == null) {
        return [];
    } else if (Array.isArray(value)) {
        return JSON.parse(JSON.stringify(value));  // solve reference issue from chaining transformers XSUP-32809
    } else {
        return value;
    }
}


function main() {
    let value = args.value;
    return getValueToSet(value);
}


try {
    return main();
} catch (error) {
    throw 'Error occurred while running the script:\n' + error;
}
