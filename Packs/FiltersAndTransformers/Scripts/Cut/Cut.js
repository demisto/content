function cut(value, fields, delim) {
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