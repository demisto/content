try {
    // Search for indicators
    const indicatorsResponse = executeCommand("findIndicators", {
        query: args.query,
        size: args.size
    });

    const indicators = indicatorsResponse[0]?.Contents || [];

    // Process the indicators
    const filteredIndicators = [];
    let fields = ['id', 'indicator_type', 'value', 'score'];

    if (args.add_fields_to_context) {
        fields = fields.concat(args.add_fields_to_context.split(",").map(field => field.trim()));
    }

    indicators.forEach(indicator => {
        const styledIndicator = {};
        fields.forEach(field => {
            styledIndicator[field] = indicator[field] || (indicator.CustomFields || {})[field] || "n/a";
        });
        styledIndicator.verdict = scoreToReputation(styledIndicator.score);
        filteredIndicators.push(styledIndicator);
    });

    // Generate table
    const headers = [...fields, "verdict"];
    const markdown = tableToMarkdown("Indicators Found", filteredIndicators, headers);
    var ec = {};
    ec["foundIndicatorsV2"] = filteredIndicators;
    // Return results
    const results = {
        Type: entryTypes.note,
        Contents: ec,
        ContentsFormat: formats.json,
        HumanReadable: markdown,
        EntryContext: ec
    };

    return results;
} catch (error) {
    throw error
}
