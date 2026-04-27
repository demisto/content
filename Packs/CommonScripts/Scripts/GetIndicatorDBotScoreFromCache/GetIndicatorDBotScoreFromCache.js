// pack version: 1.19.90
function escapeSpecialCharacters(text) {
    return text
        .replace(/\\/g, '\\\\')
        .replace(/\n/g, '\\n')
        .replace(/\t/g, '\\t')
        .replace(/\r/g, '\\r')
        .replace(/\(/g, '\\(')
        .replace(/\)/g, '\\)')
        .replace(/\[/g, '\\[')
        .replace(/\]/g, '\\]')
        .replace(/\^/g, '\\^')
        .replace(/:/g, '\\:')
        .replace(/"/g, '\\"');
}


var values = argToList(args.value)
var uniqueValues = new Set(values.map(v => v.toLowerCase()));
var uniqueValuesEscapeCharacters = Array.from(uniqueValues, item => escapeSpecialCharacters(item));
var uniqueValuesString = uniqueValuesEscapeCharacters.join('" "')

var query = `value:("${uniqueValuesString}")`;

var indicatorsRes = executeCommand('findIndicators', {
    query: query,
    populateFields: 'name,score,aggregatedReliability,type,expirationStatus'
});

  if (!isValidRes(indicatorsRes)) {
      if (indicatorsRes[0].Contents) {
          return {
              ContentsFormat: formats.markdown,
              Type: entryTypes.error,
              Contents: indicatorsRes[0].Contents
          };
      }
  }

if (indicatorsRes && indicatorsRes[0] && indicatorsRes[0]) {
    var returnEntries = [];


    for (var data of indicatorsRes[0].Contents) {
        var score = data["score"];
        var reliability = data["aggregatedReliability"];
        var indicatorType = data["indicator_type"];
        var expirationStatus = data["expirationStatus"] !== "active";
        var value = data["value"];

        var dbotScore = {
            Indicator: value,
            Type: indicatorType,
            Vendor: "XSOAR",
            Score: score,
            Reliability: reliability,
            Expired: expirationStatus
        };

        returnEntries.push(dbotScore);

        uniqueValues.delete(value.toLowerCase()); // for multiple IOCs with same value but different casing
    }

    var valuesNotFound = Array.from(new Set(
        values.filter(v => uniqueValues.has(v.toLowerCase()))
    ));

    var entries = [];

    if (returnEntries.length > 0) {
        entries.push({
            Type: entryTypes.note,
            ReadableContentsFormat: formats.markdown,
            Contents: returnEntries,
            ContentsFormat: formats.json,
            HumanReadable: tableToMarkdown('Indicator', returnEntries),
            EntryContext: {
                'DBotScoreCache': returnEntries
            }
        });
    }

    if (valuesNotFound.length == 1) {
        entries.push({
            Type: entryTypes.note,
            ReadableContentsFormat: formats.text,
            Contents: `Could not find ${valuesNotFound[0]} in cache`
        });

    }

    if (valuesNotFound.length > 1) {
        entries.push({
            Type: entryTypes.note,
            HumanReadable: tableToMarkdown('Could not find in cache', valuesNotFound, ['Values']),
            ReadableContentsFormat: formats.markdown,
            Contents: {}
        });

    }

    return entries;
}