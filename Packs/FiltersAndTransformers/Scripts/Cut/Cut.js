function parseValue(value) {
    /* This function is a workaround for an issue where passing a date field from the context
       to the "value" argument, in JS it is accepted as an object, while in python it is a string.
       To solve this discrapancy, we ensure the value is stringified correctly before running
       the cut() function. */
    if (typeof value === "string") {
        return value;
    } else if (typeof value === "number") {
        return "" + value;
    }
    value = JSON.stringify(value);
    if (value.startsWith('"') && value.endsWith('"')) {
        // potentially a date object, wrapped with quotes
        value = value.slice(1, -1);
        try {
            Date(value);
            return value;
        } catch(e) {
            // unexpected value - will throw the error below
        }
    }
    // value type isn't supported for Cut (either a boolean or a dict)
    throw "Unsupported value for Cut: " + value;
}

function cut(value, fields, delim) {
    value = parseValue(value);
    if (delim === "''") {
        delim = "";
    }

    const data = value.split(delim);
    fields = fields.split(",").map(num => parseInt(num, 10));

    const maxIndex = Math.max(...fields);
    if (data.length < maxIndex) {
        throw new Error(`Invalid field index ${maxIndex}, should be between 1 to ${data.length}.`);
    }

    return fields.map(i => data[i - 1]).join(delim);
}

return cut(args.value, args.fields, args.delimiter);
