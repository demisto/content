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

    if (value === null || (applyIfEmpty && isValueEmpty(value))) {
        value = args.defaultValue;
    }

    if (value === null) {
        return [];
    } else 
        return value;
}


function main() {
    let values = args.value;
    if (!values || (Array.isArray(values) && values.length === 0) || (values.constructor == Object && Object.keys(values).length === 0)) {
        values = [null];
    }
    values = argToList(values);

    for (let i = 0; i < values.length; i++) {
        values[i] = getValueToSet(values[i]);
    }
    return values;
}


try {
    return main();
} catch (error) {
    throw 'Error occurred while running the script:\n' + error;
}
