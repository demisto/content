function extract(values) {
    // Extracts email addresses from a list of values.
    // values: Array of strings.

    const listResults = [];

    for (const val of values) {
        listResults.push(...((val || '').toLowerCase().match(emailRegex) || []));
    }

    return listResults;
}

try {
    const values = argToList(args.value);
    const results = extract(values);
    return results;
} catch (error) {
    throw 'Error occurred while running the script:\n' + error;
}

