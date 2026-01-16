var res = executeCommand('findIndicators', {
    query: args.query,
    size: args.size
});

if (!isValidRes(res)) {
    if (res[0].Contents) {
        return {
            ContentsFormat: formats.markdown,
            Type: entryTypes.error,
            Contents: res[0].Contents
        };
    }
}

var filteredIndicators = []
if (
    res &&
    res[0] &&
    res[0].Contents
) {
    filteredIndicators = []

    fields = ["id", "indicator_type", "value", "score"]


    if (args.add_fields_to_context) {
        fields = fields.concat(args.add_fields_to_context.split(","));
        fields = fields.map(x => x.trim()); // clear out whitespace
    }

    for (var indicator of res[0].Contents) {
        var styleIndicator = {};
        for (var field of fields) {
            styleIndicator[field] =
                indicator[field] !== undefined ? indicator[field] :
                (indicator.CustomFields && indicator.CustomFields[field] !== undefined ?
                    indicator.CustomFields[field] :
                    "n/a");
        }

        styleIndicator["verdict"] = scoreToReputation(styleIndicator["score"])

        filteredIndicators.push(styleIndicator);
    }

    var headers = fields.concat(["verdict"]);

}

var ec = {
    'foundIndicators(val.id && val.id == obj.id)': filteredIndicators
};

return {
    Type: entryTypes.note,
    ReadableContentsFormat: formats.markdown,
    Contents: filteredIndicators,
    ContentsFormat: formats.json,
    HumanReadable: tableToMarkdown("Indicators Found", filteredIndicators, headers),
    EntryContext: ec,
    IgnoreAutoExtract: true
};