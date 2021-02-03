import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

DbotScoreKey = 'DBotScore(val.Indicator && val.Indicator == obj.Indicator && val.Vendor == obj.Vendor && val.Type == obj.Type)'
indicator_types = {
    'IP': "ip",
    'File SHA1': "file",
    'File MD5': "file",
    'File SHA256': "file",
    'Email': "email",
    'URL': "url"
}


def iterate_indicator_entry(indicator, entry):
    indicator_type = entry["indicator_type"]
    indicator_type = indicator_types.get(indicator_type, indicator_type)
    sources = entry.get('sourceBrands', [])
    sources = sources if sources else ['']
    for source in sources:
        dbot_score = Common.DBotScore(indicator=indicator, indicator_type=indicator_type,
                                      integration_name=source, score=entry["score"]).to_context()
        dbot_score = dbot_score.get(DbotScoreKey, dbot_score)
        yield CommandResults(readable_output=tableToMarkdown('Indicator DBot Score', dbot_score)), dbot_score


def main():
    try:
        indicator = demisto.args()['indicator']
        resp = demisto.executeCommand("getIndicator", {'value': indicator})

        if isError(resp) or not resp:
            demisto.results(resp)
            sys.exit(0)

        data = resp[0].get("Contents")

        if not data:
            demisto.results("No results.")
            sys.exit(0)
        for entry in data:
            for results, outputs in iterate_indicator_entry(indicator, entry):
                return_results(results)
                appendContext(DbotScoreKey, outputs)
    except Exception as error:
        return_error(str(error), error)


if __name__ in ('builtins', '__builtin__', '__main__'):
    main()
