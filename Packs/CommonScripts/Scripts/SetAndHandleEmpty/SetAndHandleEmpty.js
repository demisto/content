function getValue(value, stringify = false) {
    if (stringify) {
        if (value === null || value === undefined) {
            return '';
        }
        return String(value);
    } else if (!value || !(typeof value === 'string' || value instanceof Text || value instanceof Uint8Array)) {
        return value;
    } else {
        try {
            return JSON.parse(value);
        } catch (error) {
            return value;
        }
    }
}

function main() {
    let value = args.value;
    const key = args.key;
    const force = args.force === 'true';
    value = getValue(value, args.stringify === 'true');

    let humanReadable = '';
    let contextEntry = {};

    if (value || force) {
        humanReadable = `Key ${key} set`;
        contextEntry = { [key]: value };
    } else {
        humanReadable = 'value is None';
    }

    if (args.append === 'false' && Object.keys(contextEntry).length > 0) {
        executeCommand('DeleteContext', { key: key, subplaybook: 'auto' });
    }
    return {
        Type: entryTypes.note,
        EntryContext: contextEntry,
        ContentsFormat: formats.json,
        Contents: humanReadable,
        HumanReadable: humanReadable
    };
}

try {
    return main();
} catch (error) {
    throw 'Error occurred while running the script:\n' + error;
}
