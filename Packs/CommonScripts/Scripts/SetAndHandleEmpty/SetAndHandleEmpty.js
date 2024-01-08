function getValue(value, stringify = false) {
    if (stringify) {
        if (value === null || value === undefined) {
            return '';
        }
        return String(value);
    } else if (!value || !(typeof value === 'string')) {
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
    const keys = argToList(args.key);
    let value = args.value;
    const force = args.force === 'true';
    value = getValue(value, args.stringify === 'true');

    let results = [];
    for (let i = 0; i < keys.length; i++) {
        let humanReadable = '';
        let contextEntry = {};

        if (value || force) {
            humanReadable = `Key ${keys[i]} set`;
            contextEntry = { [keys[i]]: value };
        } else {
            humanReadable = 'value is None';
        }

        if (args.append === 'false' && Object.keys(contextEntry).length > 0) {
            executeCommand('DeleteContext', { key: keys[i], subplaybook: 'auto' });
        }
        results.push({
            Type: entryTypes.note,
            EntryContext: contextEntry,
            ContentsFormat: formats.json,
            Contents: humanReadable,
            HumanReadable: humanReadable
        });
    };
    return results;
}

try {
    return main();
} catch (error) {
    throw 'Error occurred while running the script:\n' + error;
}
