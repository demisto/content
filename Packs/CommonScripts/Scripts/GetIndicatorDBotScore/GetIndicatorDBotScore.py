import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


INDICATOR_TYPES = {
    'IP': DBotScoreType.IP,
    'File SHA1': DBotScoreType.FILE,
    'File MD5': DBotScoreType.FILE,
    'File SHA256': DBotScoreType.FILE,
    'Email': DBotScoreType.URL,
    'URL': DBotScoreType.URL
}


def iterate_indicator_entry(indicator, entry):
    indicator_type = entry["indicator_type"]
    indicator_type = INDICATOR_TYPES.get(indicator_type, indicator_type)
    sources = entry.get('sourceBrands', [])
    sources = sources if sources else ['']
    for source in sources:
        dbot_score = Common.DBotScore(indicator=indicator, indicator_type=indicator_type,
                                      integration_name=source, score=entry["score"]).to_context()
        dbot_score = dbot_score.get(Common.DBotScore.CONTEXT_PATH, dbot_score)
        yield dbot_score, CommandResults(readable_output=tableToMarkdown('Indicator DBot Score', dbot_score))


def main():
    try:
        indicator = demisto.args()['indicator']
        resp = demisto.executeCommand("getIndicator", {'value': indicator})

        if isError(resp) or not resp:
            demisto.results(resp)
            return

        data = resp[0].get("Contents")

        if not data:
            demisto.results("No results.")
            return
        for entry in data:
            for dbot_score, results in iterate_indicator_entry(indicator, entry):
                return_results(results)
                appendContext(Common.DBotScore.CONTEXT_PATH, dbot_score)
    except Exception as error:
        return_error(str(error), error)


if __name__ in ('builtins', '__builtin__', '__main__'):
    main()
