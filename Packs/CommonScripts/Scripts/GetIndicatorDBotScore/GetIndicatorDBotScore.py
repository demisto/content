import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

CONTEXT_PATH = 'DBotScore'
DEFAULT_SOURCE = 'Cortex XSOAR'
INDICATOR_TYPES = {
    'IP': DBotScoreType.IP,
    'File SHA1': DBotScoreType.FILE,
    'File SHA-1': DBotScoreType.FILE,
    'File MD5': DBotScoreType.FILE,
    'File SHA256': DBotScoreType.FILE,
    'File SHA-256': DBotScoreType.FILE,
    'Email': DBotScoreType.EMAIL,
    'URL': DBotScoreType.URL,
    'IPv6': DBotScoreType.IP
}


def get_dbot_score_data(indicator, indicator_type, source, score):
    db_score = Common.DBotScore(indicator=indicator, indicator_type=indicator_type,
                                integration_name=source, score=score).to_context()
    # we are using Common.DBotScore.CONTEXT_PATH for 5.5.0+ and CONTEXT_PATH for 5.0.0
    return db_score.get(Common.DBotScore.CONTEXT_PATH, db_score.get(CONTEXT_PATH, db_score))


def iterate_indicator_entry(indicator, entry):
    indicator_type = entry["indicator_type"]
    indicator_type = INDICATOR_TYPES.get(indicator_type, indicator_type).lower()
    sources = entry.get('moduleToFeedMap', {})
    if entry.get('manualScore'):
        sources[entry.get('setBy')] = {}
    elif not sources:
        sources[None] = {}
    for source, data in sources.items():
        if not source:
            source = DEFAULT_SOURCE
        dbot_score = get_dbot_score_data(indicator, indicator_type, source, data.get('score', entry["score"]))
        command_results = CommandResults(
            readable_output=tableToMarkdown('Indicator DBot Score: {}'.format(indicator), dbot_score),
            outputs={CONTEXT_PATH: dbot_score}
        ).to_context()
        context_entry_results = command_results.pop('EntryContext')[CONTEXT_PATH]
        yield context_entry_results, command_results


def main():
    try:
        # To prevent the split from succeeding.
        indicators = argToList(demisto.args()['indicator'], separator='NoSeparatorWillBeFound')
        for indicator in indicators:
            resp = demisto.executeCommand("getIndicator", {'value': indicator})

            if isError(resp) or not resp:
                demisto.results(resp)
                continue

            data = resp[0].get("Contents")

            if not data:
                demisto.results("No results found for indicator {}.".format(indicator))
                continue

            dbot_scores = []
            for entry in data:
                for dbot_score, results in iterate_indicator_entry(indicator, entry):
                    demisto.results(results)
                    dbot_scores.append(dbot_score)

            dbot_scores = dbot_scores if len(dbot_scores) > 1 or not dbot_scores else dbot_scores[0]
            appendContext(CONTEXT_PATH, dbot_scores)

    except Exception as error:
        return_error(str(error), error)


if __name__ in ('builtins', '__builtin__', '__main__'):
    main()
