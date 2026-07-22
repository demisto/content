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


function whereFieldEquals() {
    // Handles the operation of finding a list of objects where the given field is present under the specified location.

    const valuesToSearch = argToList(args.value);
    const field = args.field;
    const equalTo = args.equalTo;
    const getField = args.getField;

    const foundMatches = [];
    for (const dictItem of valuesToSearch) {
        if (typeof dictItem === 'object' && dictItem[field] === equalTo) {
            if (getField) {
                const value = dictItem[getField];
                if (value !== undefined) {
                    foundMatches.push(value);
                }
            } else {
                foundMatches.push(dictItem);
            }
        }
    }

    if (foundMatches.length === 1) {
        return foundMatches[0];
    }

    if (toBoolean(args.stringify || 'true')) {
        return JSON.stringify(foundMatches);
    } else {
        return foundMatches;
    }
}

try {
    return whereFieldEquals();
} catch (error) {
    throw 'Error occurred while running the script:\n' + error;
}
